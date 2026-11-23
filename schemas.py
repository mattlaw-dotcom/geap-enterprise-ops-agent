"""Strict Pydantic v2 input/output JSON schemas for all tools and agent reports.

Every tool validates incoming arguments against a strict input schema
(`extra="forbid"`) and returns a validated output schema (or a structured
`ToolErrorResponse` with recovery guidance). The final reporting agent uses
`IncidentTriageReport` as its ADK `output_schema` to guarantee deterministic,
machine-readable responses.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SERVICE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$")
SEMVER_PATTERN = re.compile(r"^v?\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$")


class ToolErrorResponse(BaseModel):
    """Structured error contract returning explicit recovery steps to the LLM."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["error"] = "error"
    error_code: str = Field(..., description="Machine-readable error classification code.")
    message: str = Field(..., description="Human-readable summary of what failed.")
    invalid_fields: list[str] = Field(
        default_factory=list,
        description="Input field names that failed schema or domain validation.",
    )
    recovery_instructions: str = Field(
        ...,
        description="Step-by-step instructions the LLM should follow to recover safely.",
    )
    retryable: bool = Field(
        default=True,
        description="Whether retrying the tool with corrected arguments is expected to succeed.",
    )
    suggested_next_tool: str | None = Field(
        default=None,
        description="Optional next tool name to gather missing context before retrying.",
    )
    allowed_values: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Allowed enum/catalog values for fields that failed validation.",
    )


class PendingApprovalResponse(BaseModel):
    """Structured HITL pause payload returned when human confirmation is required."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["pending_human_approval"] = "pending_human_approval"
    approval_id: str = Field(..., description="Unique approval request identifier.")
    tool_name: str = Field(..., description="High-stakes tool awaiting human confirmation.")
    risk_level: Literal["HIGH", "CRITICAL"] = Field(
        ..., description="Assessed operational risk tier."
    )
    action_summary: str = Field(
        ..., description="Plain-English summary of the proposed production mutation."
    )
    proposed_arguments: dict[str, Any] = Field(
        ..., description="PII-redacted preview of arguments pending approval."
    )
    blast_radius: str = Field(
        ..., description="Expected customer or service impact scope."
    )
    approval_instructions: str = Field(
        ...,
        description="Instructions for an authorized SRE/operator to approve or reject.",
    )


class ServiceHealthQuery(BaseModel):
    """Input schema for ``fetch_service_health_metrics``."""

    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(
        ...,
        description="Canonical kebab-case service name (e.g., 'payments-api', 'checkout-web').",
    )
    environment: Literal["prod", "staging", "dev"] = Field(
        default="prod",
        description="Target deployment environment to inspect.",
    )
    window_minutes: int = Field(
        default=15,
        ge=1,
        le=1440,
        description="Telemetry lookback window in minutes (1 to 1440).",
    )

    @field_validator("service_name")
    @classmethod
    def validate_service_name_format(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SERVICE_NAME_PATTERN.match(normalized):
            raise ValueError(
                "service_name must be 3-50 lowercase alphanumeric characters with hyphens "
                "(e.g., 'payments-api')."
            )
        return normalized


class ServiceHealthResult(BaseModel):
    """Output schema for ``fetch_service_health_metrics``."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    service_name: str
    environment: Literal["prod", "staging", "dev"]
    window_minutes: int
    health_state: Literal["HEALTHY", "DEGRADED", "CRITICAL"]
    availability_pct: float = Field(..., ge=0.0, le=100.0)
    sla_target_pct: float = Field(..., ge=0.0, le=100.0)
    sla_breached: bool
    p99_latency_ms: int = Field(..., ge=0)
    error_rate_pct: float = Field(..., ge=0.0, le=100.0)
    active_version: str
    last_good_version: str
    recent_alerts: list[str] = Field(default_factory=list)


class RunbookSearchQuery(BaseModel):
    """Input schema for ``search_incident_runbooks``."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        ...,
        min_length=3,
        max_length=300,
        description="Symptom keywords, error codes, or incident description to search.",
    )
    service_name: str | None = Field(
        default=None,
        description="Optional service filter (e.g., 'payments-api').",
    )
    top_k: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of ranked runbooks to return (1 to 10).",
    )


class RunbookMatch(BaseModel):
    """Individual ranked runbook document returned by ``search_incident_runbooks``."""

    model_config = ConfigDict(extra="forbid")

    runbook_id: str
    title: str
    service_name: str
    severity_scope: str
    relevance_score: float = Field(..., ge=0.0, le=1.0)
    recommended_steps: list[str]
    requires_human_approval: bool


class RunbookSearchResult(BaseModel):
    """Output schema for ``search_incident_runbooks``."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    query: str
    total_matches: int = Field(..., ge=0)
    runbooks: list[RunbookMatch]


class CriticalIncidentRequest(BaseModel):
    """Input schema for ``create_critical_incident_ticket``."""

    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(..., description="Affected production service name.")
    severity: Literal["P0", "P1", "P2", "P3"] = Field(
        ..., description="Incident severity level following enterprise SLA matrix."
    )
    summary: str = Field(
        ...,
        min_length=10,
        max_length=240,
        description="Concise PII-free incident headline.",
    )
    root_cause_hypothesis: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Evidence-backed hypothesis based on telemetry and runbooks.",
    )
    runbook_id: str | None = Field(
        default=None,
        description="Referenced runbook ID (e.g., 'RB-PAY-001').",
    )

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SERVICE_NAME_PATTERN.match(normalized):
            raise ValueError(
                "service_name must be lowercase kebab-case (e.g., 'payments-api')."
            )
        return normalized


class CriticalIncidentResult(BaseModel):
    """Output schema for ``create_critical_incident_ticket``."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    ticket_id: str
    service_name: str
    severity: Literal["P0", "P1", "P2", "P3"]
    summary: str
    assigned_oncall_team: str
    sla_response_minutes: int
    created_at_utc: str


class ProductionRollbackRequest(BaseModel):
    """Input schema for ``execute_production_service_rollback`` (HITL gated)."""

    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(..., description="Target production service to roll back.")
    target_version: str = Field(
        ..., description="Known-good semantic version tag (e.g., 'v2.14.1')."
    )
    incident_ticket_id: str = Field(
        ...,
        pattern=r"^INC-\d{4,8}$",
        description="Linked incident ticket ID (format: 'INC-12345').",
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Audit justification for rolling back production traffic.",
    )
    approval_token: str | None = Field(
        default=None,
        description="Verified human approval token obtained from the HITL gate.",
    )

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SERVICE_NAME_PATTERN.match(normalized):
            raise ValueError("service_name must be lowercase kebab-case.")
        return normalized

    @field_validator("target_version")
    @classmethod
    def validate_semver(cls, value: str) -> str:
        cleaned = value.strip()
        if not SEMVER_PATTERN.match(cleaned):
            raise ValueError("target_version must match semantic versioning (e.g., 'v2.14.1').")
        return cleaned


class ProductionRollbackResult(BaseModel):
    """Output schema for ``execute_production_service_rollback``."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    rollback_id: str
    service_name: str
    previous_version: str
    restored_version: str
    incident_ticket_id: str
    approved_by: str
    completed_at_utc: str


class MaintenanceWindowRequest(BaseModel):
    """Input schema for ``schedule_maintenance_window`` (HITL gated)."""

    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(..., description="Target service for scheduled maintenance.")
    start_time_utc: str = Field(
        ...,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z$",
        description="ISO-8601 UTC start timestamp (e.g., '2026-11-21T02:00:00Z').",
    )
    duration_minutes: int = Field(
        ...,
        ge=15,
        le=240,
        description="Planned maintenance duration in minutes (15 to 240).",
    )
    change_summary: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Description of maintenance changes and rollback plan.",
    )
    approval_token: str | None = Field(
        default=None,
        description="Verified human approval token obtained from the HITL gate.",
    )

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SERVICE_NAME_PATTERN.match(normalized):
            raise ValueError("service_name must be lowercase kebab-case.")
        return normalized


class MaintenanceWindowResult(BaseModel):
    """Output schema for ``schedule_maintenance_window``."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    change_id: str
    service_name: str
    start_time_utc: str
    duration_minutes: int
    approved_by: str
    notification_channels: list[str]


class IncidentTriageReport(BaseModel):
    """Final strict JSON output schema enforced on ``executive_report_agent``."""

    model_config = ConfigDict(extra="forbid")

    incident_summary: str = Field(
        ..., description="Executive summary of the incident and current status (PII-free)."
    )
    affected_service: str = Field(..., description="Primary affected service identifier.")
    severity: Literal["P0", "P1", "P2", "P3"] = Field(
        ..., description="Final assessed severity tier."
    )
    sla_status: Literal["WITHIN_SLA", "AT_RISK", "BREACHED"] = Field(
        ..., description="SLA compliance state derived from service telemetry."
    )
    root_cause_assessment: str = Field(
        ..., description="Evidence-grounded root cause assessment."
    )
    actions_taken: list[str] = Field(
        default_factory=list,
        description="Completed read-only checks, tickets created, or approved actions.",
    )
    pending_human_approvals: list[str] = Field(
        default_factory=list,
        description="High-stakes actions paused pending explicit human confirmation.",
    )
    recommended_next_steps: list[str] = Field(
        default_factory=list,
        description="Ordered operational next steps with referenced runbook IDs.",
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Self-evaluated confidence score based on telemetry and runbook evidence.",
    )


def get_tool_json_schemas() -> dict[str, dict[str, dict[str, Any]]]:
    """Exports explicit JSON Schemas (Draft 2020-12) for every tool's input and output."""
    return {
        "fetch_service_health_metrics": {
            "input": ServiceHealthQuery.model_json_schema(),
            "output": ServiceHealthResult.model_json_schema(),
            "error": ToolErrorResponse.model_json_schema(),
        },
        "search_incident_runbooks": {
            "input": RunbookSearchQuery.model_json_schema(),
            "output": RunbookSearchResult.model_json_schema(),
            "error": ToolErrorResponse.model_json_schema(),
        },
        "create_critical_incident_ticket": {
            "input": CriticalIncidentRequest.model_json_schema(),
            "output": CriticalIncidentResult.model_json_schema(),
            "error": ToolErrorResponse.model_json_schema(),
        },
        "execute_production_service_rollback": {
            "input": ProductionRollbackRequest.model_json_schema(),
            "output": ProductionRollbackResult.model_json_schema(),
            "pending_approval": PendingApprovalResponse.model_json_schema(),
            "error": ToolErrorResponse.model_json_schema(),
        },
        "schedule_maintenance_window": {
            "input": MaintenanceWindowRequest.model_json_schema(),
            "output": MaintenanceWindowResult.model_json_schema(),
            "pending_approval": PendingApprovalResponse.model_json_schema(),
            "error": ToolErrorResponse.model_json_schema(),
        },
    }
