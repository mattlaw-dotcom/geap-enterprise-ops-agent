"""Multi-agent Google ADK Enterprise Operations & Incident Triage application.

Orchestrates a 3-stage ``SequentialAgent`` pipeline wrapped in an ADK ``App``:
1. ``intake_triage_agent`` (Gemini Flash): Telemetry lookup & runbook retrieval.
2. ``remediation_planner_agent`` (Gemini Pro): Deep root-cause analysis, memory
   retrieval, incident ticketing, and HITL-gated remediation planning.
3. ``executive_report_agent`` (Gemini Flash + strict ``IncidentTriageReport``
   ``output_schema``): Final executive synthesis, self-eval, and async memory
   consolidation trigger.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.apps.app import App, ResumabilityConfig
from google.adk.memory.base_memory_service import BaseMemoryService
from google.adk.runners import Runner
from google.adk.sessions import BaseSessionService
from google.adk.tools import VertexAiSearchTool, load_memory
from google.genai import types

from agent_app.config.secrets import AppSettings, get_settings
from agent_app.guardrails.hitl import HumanApprovalGate, get_default_hitl_gate
from agent_app.guardrails.policy_plugin import EnterprisePolicyGuardrailPlugin
from agent_app.memory.compaction import (
    ContextCompactor,
    build_adk_compaction_config,
    build_context_cache_config,
)
from agent_app.memory.memory_manager import (
    AsyncMemoryConsolidator,
    create_memory_service,
)
from agent_app.memory.session_store import create_session_service
from agent_app.observability.logging_config import configure_structured_logging, get_logger
from agent_app.observability.observability_plugin import ObservabilityPlugin
from agent_app.observability.pii_redactor import PIIRedactor, get_default_redactor
from agent_app.observability.tracing import configure_tracing
from agent_app.prompts import (
    EXECUTIVE_REPORT_INSTRUCTION,
    INTAKE_TRIAGE_INSTRUCTION,
    REMEDIATION_PLANNER_INSTRUCTION,
    SYSTEM_CONSTITUTION,
)
from agent_app.routing import ModelRouter
from agent_app.schemas import IncidentTriageReport
from agent_app.tools.ops_tools import (
    create_critical_incident_ticket_tool,
    execute_production_service_rollback_tool,
    fetch_service_health_metrics_tool,
    schedule_maintenance_window_tool,
    search_incident_runbooks_tool,
)

# Initialize structured JSON logging & OpenTelemetry tracing on module import.
configure_structured_logging()
configure_tracing(service_name="geap-enterprise-ops-agent")
logger = get_logger("geap.agent")


def build_agent_app(
    *,
    settings: AppSettings | None = None,
    hitl_gate: HumanApprovalGate | None = None,
    redactor: PIIRedactor | None = None,
    memory_service: BaseMemoryService | None = None,
) -> tuple[
    App,
    SequentialAgent,
    ObservabilityPlugin,
    EnterprisePolicyGuardrailPlugin,
    AsyncMemoryConsolidator,
]:
    """Constructs the complete ADK multi-agent pipeline, plugins, and async consolidator."""
    cfg = settings or get_settings()
    active_redactor = redactor or get_default_redactor()
    active_hitl = hitl_gate or get_default_hitl_gate()
    active_memory = memory_service or create_memory_service(settings=cfg)
    consolidator = AsyncMemoryConsolidator(active_memory, redactor=active_redactor)
    router = ModelRouter(
        flash_model=cfg.flash_model,
        pro_model=cfg.pro_model,
        settings=cfg,
    )
    compactor = ContextCompactor(
        max_token_budget=cfg.compaction_token_threshold,
        redactor=active_redactor,
    )

    observability_plugin = ObservabilityPlugin(redactor=active_redactor)
    guardrail_plugin = EnterprisePolicyGuardrailPlugin(
        hitl_gate=active_hitl,
        redactor=active_redactor,
        compactor=compactor,
        model_armor_template_id=cfg.model_armor_template_id,
    )

    async def _after_report_async_consolidation(
        callback_context: CallbackContext,
    ) -> Optional[types.Content]:
        """Triggers non-blocking background memory consolidation after Stage 3 completes."""
        state = getattr(callback_context, "state", None)
        report_payload = state.get("final_incident_report") if hasattr(state, "get") else None
        if report_payload:
            session_obj = getattr(callback_context, "session", None)
            session_id = (
                getattr(session_obj, "id", None)
                or getattr(callback_context, "invocation_id", None)
                or "session"
            )
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    consolidator.schedule_fact_consolidation(
                        app_name=cfg.app_name,
                        user_id=getattr(callback_context, "user_id", None) or "enterprise-operator",
                        session_id=str(session_id),
                        raw_fact=str(report_payload),
                        tags=["incident_report", "post_triage"],
                    )
            except RuntimeError:
                pass
        return None

    intake_tools: list[Any] = [
        fetch_service_health_metrics_tool,
        search_incident_runbooks_tool,
    ]
    if cfg.vertex_ai_datastore_id:
        intake_tools.append(
            VertexAiSearchTool(
                data_store_id=cfg.vertex_ai_datastore_id,
                bypass_multi_tools_limit=True,
            )
        )

    # Stage 1: Fast Intake & Telemetry Triage (Gemini Flash + dynamic escalation hook)
    intake_triage_agent = LlmAgent(
        name="intake_triage_agent",
        model=router.flash_model,
        description=(
            "Fast Flash-tier intake specialist that inspects live service telemetry "
            "and retrieves matching enterprise SRE runbooks."
        ),
        instruction=f"{SYSTEM_CONSTITUTION}\n\n{INTAKE_TRIAGE_INSTRUCTION}",
        tools=intake_tools,
        before_model_callback=router.build_before_model_callback(task_role="intake_triage"),
        output_key="triage_findings",
    )

    # Stage 2: Deep Root-Cause & Remediation Planner (Gemini Pro + HITL tools + memory)
    remediation_planner_agent = LlmAgent(
        name="remediation_planner_agent",
        model=router.pro_model,
        description=(
            "Pro-tier remediation architect performing root-cause analysis, memory "
            "retrieval, incident ticketing, and HITL-gated remediation planning."
        ),
        instruction=f"{SYSTEM_CONSTITUTION}\n\n{REMEDIATION_PLANNER_INSTRUCTION}",
        tools=[
            create_critical_incident_ticket_tool,
            execute_production_service_rollback_tool,
            schedule_maintenance_window_tool,
            load_memory,
        ],
        before_model_callback=router.build_before_model_callback(
            task_role="remediation_planner"
        ),
        output_key="remediation_plan",
    )

    # Stage 3: Executive Report Synthesizer (Gemini Flash + strict Pydantic output_schema)
    executive_report_agent = LlmAgent(
        name="executive_report_agent",
        model=router.flash_model,
        description=(
            "Flash-tier executive synthesizer generating a strictly schema-validated "
            "IncidentTriageReport and triggering async long-term memory consolidation."
        ),
        instruction=f"{SYSTEM_CONSTITUTION}\n\n{EXECUTIVE_REPORT_INSTRUCTION}",
        output_schema=IncidentTriageReport,
        output_key="final_incident_report",
        before_model_callback=router.build_before_model_callback(task_role="executive_report"),
        after_agent_callback=_after_report_async_consolidation,
    )

    pipeline = SequentialAgent(
        name="enterprise_ops_triage_pipeline",
        description=(
            "Sequential 3-stage enterprise incident triage, remediation planning, "
            "and executive reporting workflow with Flash/Pro routing, guardrails, and HITL."
        ),
        sub_agents=[
            intake_triage_agent,
            remediation_planner_agent,
            executive_report_agent,
        ],
    )

    adk_app = App(
        name=cfg.app_name,
        root_agent=pipeline,
        plugins=[observability_plugin, guardrail_plugin],
        events_compaction_config=build_adk_compaction_config(
            flash_model=cfg.flash_model,
            compaction_interval=cfg.compaction_interval,
            overlap_size=cfg.compaction_overlap_size,
            token_threshold=cfg.compaction_token_threshold,
            event_retention_size=cfg.compaction_retention_size,
        ),
        context_cache_config=build_context_cache_config(),
        resumability_config=ResumabilityConfig(is_resumable=True),
    )

    return adk_app, pipeline, observability_plugin, guardrail_plugin, consolidator


# Canonical module-level exports required by `adk run`, `adk web`, `adk eval`, and Agent Engine.
(
    app,
    root_agent,
    observability_plugin,
    guardrail_plugin,
    memory_consolidator,
) = build_agent_app()


def build_runner(
    *,
    adk_app: App | None = None,
    session_service: BaseSessionService | None = None,
    memory_service: BaseMemoryService | None = None,
    settings: AppSettings | None = None,
) -> Runner:
    """Builds a production-configured ADK ``Runner`` backed by persistent session & memory stores."""
    cfg = settings or get_settings()
    return Runner(
        app=adk_app or app,
        session_service=session_service or create_session_service(settings=cfg),
        memory_service=memory_service or create_memory_service(settings=cfg),
        auto_create_session=True,
    )


async def run_enterprise_ops_workflow(
    user_prompt: str,
    *,
    user_id: str = "sre-operator",
    session_id: str | None = None,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    """Executes one full turn of the Enterprise Ops ADK Runner and returns event summaries."""
    active_runner = runner or build_runner()
    resolved_session_id = session_id or "ops-session-default"
    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_prompt)],
    )
    events_summary: list[dict[str, Any]] = []
    async for event in active_runner.run_async(
        user_id=user_id,
        session_id=resolved_session_id,
        new_message=content,
    ):
        text_parts = [
            part.text
            for part in (event.content.parts if event.content and event.content.parts else [])
            if getattr(part, "text", None)
        ]
        events_summary.append(
            {
                "author": event.author,
                "text": "\n".join(text_parts),
                "is_final": event.is_final_response(),
            }
        )
    return events_summary
