"""Category 1 Tests: Tool & Interface Design (docstrings, naming, JSON schemas, error recovery)."""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from agent_app.schemas import (
    CriticalIncidentRequest,
    CriticalIncidentResult,
    IncidentTriageReport,
    RunbookSearchResult,
    ServiceHealthQuery,
    ServiceHealthResult,
    ToolErrorResponse,
    get_tool_json_schemas,
)
from agent_app.tools.ops_tools import (
    create_critical_incident_ticket,
    execute_production_service_rollback,
    fetch_service_health_metrics,
    get_all_ops_tools,
    schedule_maintenance_window,
    search_incident_runbooks,
)


def test_all_tools_have_comprehensive_docstrings_and_descriptive_names() -> None:
    expected_names = {
        "fetch_service_health_metrics",
        "search_incident_runbooks",
        "create_critical_incident_ticket",
        "execute_production_service_rollback",
        "schedule_maintenance_window",
    }
    tools = get_all_ops_tools()
    actual_names = {tool.name for tool in tools}
    assert actual_names == expected_names

    for tool in tools:
        doc = inspect.getdoc(tool.func)
        assert doc is not None and len(doc) >= 150, f"Tool '{tool.name}' docstring is too short."
        assert "Args:" in doc, f"Tool '{tool.name}' docstring missing Args section."
        assert "Returns:" in doc, f"Tool '{tool.name}' docstring missing Returns section."
        assert "_" in tool.name and len(tool.name.split("_")) >= 3


def test_explicit_pydantic_input_and_output_json_schemas() -> None:
    exported = get_tool_json_schemas()
    for tool in get_all_ops_tools():
        assert tool.name in exported
        schemas = tool.get_json_schemas()
        assert schemas["input_schema"]["type"] == "object"
        assert schemas["output_schema"]["type"] == "object"
        assert schemas["input_schema"].get("additionalProperties") is False
        assert schemas["output_schema"].get("additionalProperties") is False

        declaration = tool._get_declaration()
        assert declaration is not None
        assert declaration.name == tool.name
        assert declaration.parameters_json_schema is not None
        assert "properties" in declaration.parameters_json_schema


def test_pydantic_schemas_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ServiceHealthQuery(service_name="payments-api", unexpected_param="bad")  # type: ignore[call-arg]

    with pytest.raises(ValidationError):
        CriticalIncidentRequest(
            service_name="payments-api",
            severity="P0",
            summary="Payments outage on /v2/charges",
            root_cause_hypothesis="Connection pool exhaustion after deployment.",
            rogue_flag=True,  # type: ignore[call-arg]
        )


def test_fetch_service_health_metrics_happy_path_and_guided_error_recovery() -> None:
    ok_res = fetch_service_health_metrics("payments-api", environment="prod", window_minutes=15)
    parsed = ServiceHealthResult.model_validate(ok_res)
    assert parsed.health_state == "CRITICAL"
    assert parsed.sla_breached is True
    assert parsed.active_version == "v2.15.0"
    assert parsed.last_good_version == "v2.14.2"

    # Unknown service returns guided ToolErrorResponse rather than raising
    unknown_res = fetch_service_health_metrics("unknown-svc")
    err = ToolErrorResponse.model_validate(unknown_res)
    assert err.error_code == "UNKNOWN_SERVICE"
    assert err.retryable is True
    assert "payments-api" in err.allowed_values["service_name"]
    assert err.suggested_next_tool == "search_incident_runbooks"
    assert "allowed_values" in err.recovery_instructions

    # Schema validation error (window_minutes out of range) returns guided recovery
    bad_window = fetch_service_health_metrics("payments-api", window_minutes=99999)
    err2 = ToolErrorResponse.model_validate(bad_window)
    assert err2.error_code == "SCHEMA_VALIDATION_ERROR"
    assert "window_minutes" in err2.invalid_fields
    assert "1440" in err2.recovery_instructions


def test_search_runbooks_and_create_ticket_validate_schemas() -> None:
    rb_res = search_incident_runbooks("payments 503 connection pool", service_name="payments-api")
    parsed_rb = RunbookSearchResult.model_validate(rb_res)
    assert parsed_rb.total_matches >= 1
    assert parsed_rb.runbooks[0].runbook_id == "RB-PAY-001"
    assert parsed_rb.runbooks[0].requires_human_approval is True

    # Short invalid query returns guided error
    bad_rb = search_incident_runbooks("a")
    err = ToolErrorResponse.model_validate(bad_rb)
    assert err.error_code == "SCHEMA_VALIDATION_ERROR"

    ticket_res = create_critical_incident_ticket(
        service_name="payments-api",
        severity="P0",
        summary="Payments API P0 outage with 6.3% 503 errors",
        root_cause_hypothesis="Connection pool saturation introduced in v2.15.0.",
        runbook_id="RB-PAY-001",
    )
    parsed_ticket = CriticalIncidentResult.model_validate(ticket_res)
    assert parsed_ticket.ticket_id.startswith("INC-")
    assert parsed_ticket.sla_response_minutes == 15


def test_rollback_and_maintenance_guided_errors_without_crashing() -> None:
    # Rolling back to the currently active broken version returns explicit recovery instructions
    same_ver = execute_production_service_rollback(
        service_name="payments-api",
        target_version="v2.15.0",
        incident_ticket_id="INC-12345",
        reason="Attempting rollback to current version by mistake.",
    )
    err = ToolErrorResponse.model_validate(same_ver)
    assert err.error_code == "INVALID_ROLLBACK_TARGET"
    assert err.allowed_values["target_version"] == ["v2.14.2"]
    assert "v2.14.2" in err.recovery_instructions

    # Invalid ISO timestamp in schedule_maintenance_window returns guided error
    bad_ts = schedule_maintenance_window(
        service_name="orders-db",
        start_time_utc="tomorrow morning",
        duration_minutes=60,
        change_summary="Rebuild primary PostgreSQL indexes safely.",
    )
    err2 = ToolErrorResponse.model_validate(bad_ts)
    assert err2.error_code == "SCHEMA_VALIDATION_ERROR"
    assert "start_time_utc" in err2.invalid_fields


def test_executive_incident_triage_report_schema() -> None:
    report = IncidentTriageReport(
        incident_summary="payments-api experienced P0 503 outage in prod.",
        affected_service="payments-api",
        severity="P0",
        sla_status="BREACHED",
        root_cause_assessment="Connection pool saturation after v2.15.0 release.",
        actions_taken=["Fetched telemetry", "Created INC-55432"],
        pending_human_approvals=["APR-12345678: rollback to v2.14.2"],
        recommended_next_steps=["Approve APR-12345678", "Verify error rate drops < 0.5%"],
        confidence_score=0.94,
    )
    assert report.model_dump(mode="json")["sla_status"] == "BREACHED"
