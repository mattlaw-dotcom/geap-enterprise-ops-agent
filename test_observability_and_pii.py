"""Category 4 Tests: Structured JSON Logging, Intent vs. Outcome, OTel Tracing, PII Redaction."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent_app.observability.logging_config import configure_structured_logging, get_logger
from agent_app.observability.observability_plugin import ObservabilityPlugin
from agent_app.observability.pii_redactor import PIIRedactor
from agent_app.observability.tracing import traced_operation
from agent_app.tools.ops_tools import fetch_service_health_metrics_tool


@dataclass
class _StubToolCtx:
    agent_name: str = "intake_triage_agent"
    function_call_id: str = "fc-trace-99"


@dataclass
class _StubInvocationCtx:
    invocation_id: str = "inv-otel-42"
    app_name: str = "geap_enterprise_ops_agent"
    session: Any = None

    def __post_init__(self) -> None:
        if self.session is None:
            self.session = SimpleNamespace(id="sess-otel-99")


@dataclass
class _StubAgent:
    name: str = "intake_triage_agent"


@dataclass
class _StubCallbackCtx:
    agent_name: str = "intake_triage_agent"
    invocation_id: str = "inv-otel-42"


def test_structured_json_logging_includes_trace_context_and_redacts_pii(
    otel_exporter: InMemorySpanExporter,
) -> None:
    buffer = io.StringIO()
    configure_structured_logging(stream=buffer, redactor=PIIRedactor(enable_cloud_dlp=False))
    log = get_logger("geap.test.json")

    with traced_operation("test.parent_span", attributes={"env": "test"}):
        log.info(
            "incident.alert.received",
            reporter="sre.person@example.com",
            phone="415-555-0199",
            api_key="super-secret-value",
            notes="SSN 123-45-6789 hit 503",
        )

    lines = [line for line in buffer.getvalue().strip().splitlines() if line.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["event"] == "incident.alert.received"
    assert payload["level"] == "info"
    assert "timestamp_utc" in payload
    assert payload["trace_id"] != "0" * 32
    assert payload["span_id"] != "0" * 16
    assert payload["reporter"] == "[REDACTED_EMAIL]"
    assert payload["phone"] == "[REDACTED_PHONE]"
    assert payload["api_key"] == "[REDACTED_SECRET]"
    assert "123-45-6789" not in payload["notes"]


@pytest.mark.asyncio
async def test_intent_vs_outcome_capture_and_linked_otel_spans(
    otel_exporter: InMemorySpanExporter,
) -> None:
    buffer = io.StringIO()
    redactor = PIIRedactor(enable_cloud_dlp=False)
    configure_structured_logging(stream=buffer, redactor=redactor)
    plugin = ObservabilityPlugin(redactor=redactor)

    inv_ctx = _StubInvocationCtx()
    cb_ctx = _StubCallbackCtx()
    tool_ctx = _StubToolCtx()
    agent = _StubAgent()

    await plugin.before_run_callback(invocation_context=inv_ctx)  # type: ignore[arg-type]
    await plugin.before_agent_callback(agent=agent, callback_context=cb_ctx)  # type: ignore[arg-type]
    await plugin.before_tool_callback(
        tool=fetch_service_health_metrics_tool,
        tool_args={"service_name": "payments-api", "reporter": "alice@example.com"},
        tool_context=tool_ctx,  # type: ignore[arg-type]
    )
    await plugin.after_tool_callback(
        tool=fetch_service_health_metrics_tool,
        tool_args={"service_name": "payments-api"},
        tool_context=tool_ctx,  # type: ignore[arg-type]
        result={"status": "ok", "health_state": "CRITICAL"},
    )
    await plugin.after_agent_callback(agent=agent, callback_context=cb_ctx)  # type: ignore[arg-type]
    await plugin.after_run_callback(invocation_context=inv_ctx)  # type: ignore[arg-type]

    # Verify correlated Intent vs. Outcome structured JSON log entries
    json_logs = [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]
    intent_logs = [entry for entry in json_logs if entry.get("event") == "agent.action.intent"]
    outcome_logs = [entry for entry in json_logs if entry.get("event") == "agent.action.outcome"]
    assert len(intent_logs) == 2  # agent_stage + tool_call
    assert len(outcome_logs) == 2

    tool_intent = next(e for e in intent_logs if e.get("action_type") == "tool_call")
    tool_outcome = next(e for e in outcome_logs if e.get("action_type") == "tool_call")
    assert tool_intent["intent_id"] == tool_outcome["intent_id"]
    assert tool_intent["tool_args"]["reporter"] == "[REDACTED_EMAIL]"
    assert tool_outcome["outcome_status"] == "success"
    assert tool_outcome["intent_matched_outcome"] is True

    # Verify in-memory audit records
    records = plugin.get_intent_outcome_records()
    assert len(records) == 2
    assert any(r.action_name == "fetch_service_health_metrics" and r.intent_matched_outcome for r in records)

    # Verify linked OpenTelemetry distributed spans share one root trace_id
    spans = otel_exporter.get_finished_spans()
    span_names = {s.name for s in spans}
    assert "adk.invocation.run" in span_names
    assert "adk.agent.intake_triage_agent" in span_names
    assert "adk.tool.fetch_service_health_metrics" in span_names

    trace_ids = {s.context.trace_id for s in spans}
    assert len(trace_ids) == 1
    tool_span = next(s for s in spans if s.name == "adk.tool.fetch_service_health_metrics")
    agent_span = next(s for s in spans if s.name == "adk.agent.intake_triage_agent")
    assert tool_span.parent is not None
    assert tool_span.parent.span_id == agent_span.context.span_id


def test_pii_redactor_cloud_dlp_integration_and_regex_fallback() -> None:
    # 1. Regex fallback redacts all major PII and credential patterns
    fallback_redactor = PIIRedactor(enable_cloud_dlp=False)
    synthetic_api_key = "AIza" + "FAKE0000000000000000TESTKEY"
    sample = (
        "Email jane.doe@example.com, SSN 123-45-6789, Phone (415) 555-0199, "
        "Card 4532-0151-1283-0366, IP 10.24.18.9, "
        f"Key {synthetic_api_key}, Header Bearer eyJhbGciOiJIUzI1NiJ9.abc.def"
    )
    report = fallback_redactor.redact_with_report(sample)
    assert report.backend == "regex_fallback"
    assert report.redactions_count >= 7
    for raw_secret in (
        "jane.doe@example.com",
        "123-45-6789",
        "415",
        "4532-0151-1283-0366",
        "10.24.18.9",
        synthetic_api_key,
        "eyJhbGciOiJIUzI1NiJ9",
    ):
        assert raw_secret not in report.redacted_text

    # 2. Mocked Google Cloud DLP client path
    class _MockDlpClient:
        def __init__(self) -> None:
            self.called_parent: str | None = None

        def deidentify_content(self, *, request: dict[str, Any]) -> Any:
            self.called_parent = request["parent"]
            val = request["item"]["value"].replace("cto@example.com", "[EMAIL_ADDRESS]")
            return SimpleNamespace(
                item=SimpleNamespace(value=val),
                overview=SimpleNamespace(
                    transformation_summaries=[
                        SimpleNamespace(
                            info_type=SimpleNamespace(name="EMAIL_ADDRESS"),
                            results=[SimpleNamespace(count=1)],
                        )
                    ]
                ),
            )

    mock_dlp = _MockDlpClient()
    dlp_redactor = PIIRedactor(
        project_id="demo-gcp-proj",
        enable_cloud_dlp=True,
        dlp_client=mock_dlp,
    )
    dlp_report = dlp_redactor.redact_with_report("Escalation for cto@example.com")
    assert mock_dlp.called_parent == "projects/demo-gcp-proj/locations/global"
    assert dlp_report.backend == "cloud_dlp+regex"
    assert "cto@example.com" not in dlp_report.redacted_text
    assert "[EMAIL_ADDRESS]" in dlp_report.redacted_text

    # 3. Graceful fallback when Cloud DLP raises an error
    class _FailingDlpClient:
        def deidentify_content(self, *, request: dict[str, Any]) -> Any:
            raise RuntimeError("DLP API unavailable offline")

    resilient = PIIRedactor(
        project_id="demo-gcp-proj",
        enable_cloud_dlp=True,
        dlp_client=_FailingDlpClient(),
    )
    res_text = resilient.redact_text("Contact fallback@example.com")
    assert "fallback@example.com" not in res_text
    assert "[REDACTED_EMAIL]" in res_text
