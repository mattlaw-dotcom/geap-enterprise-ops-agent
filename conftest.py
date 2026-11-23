"""Shared pytest fixtures providing isolated SQLite stores, HITL reset, and OTel exporter."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent_app.guardrails.hitl import get_default_hitl_gate
from agent_app.memory import session_store
from agent_app.observability.tracing import configure_tracing


@pytest.fixture(autouse=True)
def isolated_runtime_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Isolates SQLite DB files and HITL state per test so tests never pollute repo state."""
    knowledge_db = tmp_path / "ops_knowledge.db"
    memory_db = tmp_path / "ops_memory.db"
    sessions_db = tmp_path / "ops_sessions.db"

    monkeypatch.setenv("OPS_KNOWLEDGE_DB_PATH", str(knowledge_db))
    monkeypatch.setenv("OPS_MEMORY_DB_PATH", str(memory_db))
    monkeypatch.setenv("OPS_DATABASE_URL", f"sqlite+aiosqlite:///{sessions_db}")
    monkeypatch.setenv("ENABLE_CLOUD_DLP", "false")
    monkeypatch.setenv("USE_SECRET_MANAGER", "false")

    session_store._DEFAULT_STORE = None
    get_default_hitl_gate().clear()

    yield tmp_path

    session_store._DEFAULT_STORE = None
    get_default_hitl_gate().clear()
    # Ensure no stray env leakage
    os.environ.pop("ENABLE_MODEL_ARMOR", None)


@pytest.fixture
def otel_exporter() -> InMemorySpanExporter:
    """Configures an in-memory OpenTelemetry span exporter for trace assertions."""
    _, exporter = configure_tracing(
        service_name="geap-enterprise-ops-agent-test",
        environment="test",
        use_in_memory_exporter=True,
    )
    assert exporter is not None
    exporter.clear()
    return exporter
