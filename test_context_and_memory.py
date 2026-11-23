"""Category 2 Tests: Context & Memory (constitution, compaction, persistent DB, async memory)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
from google.adk.models.llm_request import LlmRequest
from google.adk.sessions import DatabaseSessionService
from google.genai import types

from agent_app.agent import app
from agent_app.memory.compaction import (
    ContextCompactor,
    build_adk_compaction_config,
    build_context_cache_config,
)
from agent_app.memory.memory_manager import (
    AsyncMemoryConsolidator,
    PersistentSQLiteMemoryService,
)
from agent_app.memory.session_store import (
    PersistentOpsKnowledgeStore,
    create_session_service,
)
from agent_app.prompts import (
    EXECUTIVE_REPORT_INSTRUCTION,
    INTAKE_TRIAGE_INSTRUCTION,
    REMEDIATION_PLANNER_INSTRUCTION,
    SYSTEM_CONSTITUTION,
)


def test_robust_system_constitution_and_stage_prompts() -> None:
    for required_concept in (
        "Persona",
        "P0",
        "P1",
        "Zero Fabrication",
        "Human-in-the-Loop",
        "Guided Error Recovery",
        "PII",
        "Prompt Injection",
    ):
        assert required_concept in SYSTEM_CONSTITUTION

    assert "{triage_findings}" in REMEDIATION_PLANNER_INSTRUCTION
    assert "{triage_findings}" in EXECUTIVE_REPORT_INSTRUCTION
    assert "{remediation_plan}" in EXECUTIVE_REPORT_INSTRUCTION
    assert "fetch_service_health_metrics" in INTAKE_TRIAGE_INSTRUCTION


def test_adk_native_compaction_and_context_cache_configured_on_app() -> None:
    assert app.events_compaction_config is not None
    assert app.events_compaction_config.token_threshold == 4000
    assert app.events_compaction_config.compaction_interval == 5
    assert app.events_compaction_config.summarizer is not None

    assert app.context_cache_config is not None
    assert app.context_cache_config.min_tokens == 1024
    assert app.context_cache_config.ttl_seconds == 600

    cfg = build_adk_compaction_config(token_threshold=2048, compaction_interval=3)
    assert cfg.token_threshold == 2048
    cache_cfg = build_context_cache_config(min_tokens=512, ttl_seconds=300)
    assert cache_cfg.ttl_seconds == 300


def test_sliding_window_history_compactor_reduces_tokens_and_redacts_pii() -> None:
    compactor = ContextCompactor(max_token_budget=120, recent_turns_to_keep=2, summary_max_chars=300)
    turns = [
        {"role": "system", "content": "Follow the Enterprise Ops Agent Constitution."},
        {
            "role": "user",
            "content": "Alert from alice.ops@example.com about payments-api 503 error spike " * 8,
        },
        {"role": "assistant", "content": "Checked metrics for payments-api and found pool saturation " * 8},
        {"role": "user", "content": "Also check checkout-web latency and SSN 123-45-6789 " * 6},
        {"role": "assistant", "content": "Retrieved RB-PAY-001 and RB-CHK-002 runbooks."},
        {"role": "user", "content": "Proceed with P0 incident ticket creation now."},
    ]

    result = compactor.compact_history(turns)
    assert result.compacted is True
    assert result.tokens_saved > 0
    assert result.resulting_turn_count < result.original_turn_count
    assert result.turns[0]["role"] == "system"
    assert result.summary_text is not None
    assert "alice.ops@example.com" not in result.summary_text
    assert "123-45-6789" not in result.summary_text

    # Also verify LlmRequest in-place compaction
    req = LlmRequest(
        model="gemini-2.5-flash",
        contents=[
            types.Content(role="user", parts=[types.Part.from_text(text=t["content"])])
            for t in turns[1:]
        ],
    )
    req_res = compactor.compact_llm_request(req)
    assert req_res.compacted is True
    assert len(req.contents) == 3  # 1 summary + 2 retained turns


@pytest.mark.asyncio
async def test_persistent_database_session_service_survives_restarts(tmp_path: Path) -> None:
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'durable_sessions.db'}"
    svc1 = create_session_service(db_url=db_url)
    assert isinstance(svc1, DatabaseSessionService)

    created = await svc1.create_session(
        app_name="geap_enterprise_ops_agent",
        user_id="sre-alice",
        state={"active_incident_ticket_id": "INC-90210", "incident_severity": "P0"},
    )
    await svc1.close()

    # Re-open a brand-new DatabaseSessionService against the same SQLite file
    svc2 = create_session_service(db_url=db_url)
    reloaded = await svc2.get_session(
        app_name="geap_enterprise_ops_agent",
        user_id="sre-alice",
        session_id=created.id,
    )
    assert reloaded is not None
    assert reloaded.state["active_incident_ticket_id"] == "INC-90210"
    assert reloaded.state["incident_severity"] == "P0"
    await svc2.close()


def test_persistent_ops_knowledge_store_persists_runbooks_and_tickets(tmp_path: Path) -> None:
    db_file = tmp_path / "knowledge.db"
    store1 = PersistentOpsKnowledgeStore(db_path=db_file)
    matches = store1.search_runbooks("jwt 401 token signature failure", service_name="auth-gateway")
    assert len(matches) >= 1
    assert matches[0]["runbook_id"] == "RB-AUTH-003"

    store1.save_incident_ticket(
        {
            "ticket_id": "INC-77777",
            "service_name": "auth-gateway",
            "severity": "P0",
            "summary": "Auth outage reported by bob@example.com",
            "root_cause_hypothesis": "JWT key mismatch after deploy",
            "runbook_id": "RB-AUTH-003",
            "assigned_oncall_team": "identity-sre@enterprise.example",
            "sla_response_minutes": 15,
            "created_at_utc": "2026-11-20T15:00:00+00:00",
        }
    )

    # Re-instantiate against same SQLite path to verify persistence + PII scrubbing
    store2 = PersistentOpsKnowledgeStore(db_path=db_file)
    ticket = store2.get_incident_ticket("INC-77777")
    assert ticket is not None
    assert "bob@example.com" not in ticket["summary"]
    assert "[REDACTED_EMAIL]" in ticket["summary"]


@pytest.mark.asyncio
async def test_async_memory_consolidation_is_non_blocking_and_scrubs_pii(tmp_path: Path) -> None:
    mem_service = PersistentSQLiteMemoryService(db_path=tmp_path / "long_term_mem.db")
    consolidator = AsyncMemoryConsolidator(mem_service)

    start = time.perf_counter()
    task = consolidator.schedule_fact_consolidation(
        app_name="geap_enterprise_ops_agent",
        user_id="sre-alice",
        session_id="sess-42",
        raw_fact=(
            "Resolved payments-api P0 incident INC-40219 via rollback to v2.14.2. "
            "Reporter contact: pager.alice@example.com, phone 415-555-0142."
        ),
        tags=["payments-api", "rollback"],
        simulated_delay_seconds=0.15,
    )
    elapsed_schedule = time.perf_counter() - start
    # Scheduling must return immediately without blocking on the 150ms consolidation task
    assert elapsed_schedule < 0.05
    assert isinstance(task, asyncio.Task)
    assert consolidator.pending_count == 1

    await consolidator.drain(timeout=5.0)
    assert consolidator.pending_count == 0
    assert consolidator.completed_count == 1

    search_resp = await mem_service.search_memory(
        app_name="geap_enterprise_ops_agent",
        user_id="sre-alice",
        query="payments-api rollback",
    )
    assert len(search_resp.memories) == 1
    stored_text = search_resp.memories[0].content.parts[0].text
    assert "INC-40219" in stored_text
    assert "pager.alice@example.com" not in stored_text
    assert "415-555-0142" not in stored_text
    assert "[REDACTED_EMAIL]" in stored_text
