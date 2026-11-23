"""Strategic Flash vs. Pro Model Routing for Cost, Latency, and Reasoning Depth.

Routes tasks strategically across Gemini model tiers:
- **Flash (`gemini-2.5-flash`)**: Low-latency, high-throughput tasks such as
  intake triage, telemetry lookup coordination, history compaction, and final
  executive report formatting.
- **Pro (`gemini-2.5-pro`)**: High-complexity tasks such as multi-service root
  cause analysis, blast-radius evaluation, P0 outage remediation planning, and
  risky production rollback decisions.

Includes a dynamic ADK ``before_model_callback`` capable of escalating a Flash
stage to Pro at runtime when P0/cascading-failure complexity signals appear.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Optional

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from pydantic import BaseModel, ConfigDict, Field

from agent_app.config.secrets import AppSettings, get_settings
from agent_app.memory.compaction import extract_text_from_contents
from agent_app.observability.logging_config import get_logger
from agent_app.observability.tracing import traced_operation

_HIGH_COMPLEXITY_PATTERNS = (
    re.compile(r"(?i)\b(?:p0|sev0|sev-0|cascading\s+failure|multi-region\s+outage|outage)\b"),
    re.compile(r"(?i)\b(?:production\s+rollback|roll\s*back|root\s+cause\s+analysis|blast\s+radius|failover)\b"),
    re.compile(r"(?i)\b(?:deadlock|data\s+corruption|split-brain|security\s+breach)\b"),
)


class TaskComplexity(str, Enum):
    """Operational complexity tier governing Gemini model selection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModelSelectionDecision(BaseModel):
    """Auditable record of why a specific Gemini model tier was chosen."""

    model_config = ConfigDict(extra="forbid")

    selected_model: str
    tier: str = Field(..., description="'flash' or 'pro'")
    complexity: TaskComplexity
    task_role: str
    escalated: bool = False
    rationale: str


class ModelRouter:
    """Routes ADK agent stages and dynamic requests between Gemini Flash and Pro."""

    PRO_ROLES = frozenset(
        {"remediation_planner", "root_cause_analysis", "architecture_review"}
    )
    FLASH_ROLES = frozenset(
        {"intake_triage", "executive_report", "compaction", "classification"}
    )
    PINNED_FLASH_ROLES = frozenset({"executive_report", "compaction", "classification"})

    def __init__(
        self,
        *,
        flash_model: str | None = None,
        pro_model: str | None = None,
        settings: AppSettings | None = None,
    ) -> None:
        cfg = settings or get_settings()
        self.flash_model = flash_model or cfg.flash_model
        self.pro_model = pro_model or cfg.pro_model
        self.logger = get_logger("geap.routing")

    def select_model(
        self,
        *,
        task_role: str,
        prompt_text: str = "",
        severity: str | None = None,
        token_estimate: int = 0,
    ) -> ModelSelectionDecision:
        """Selects Gemini Flash or Pro based on role, severity, and prompt complexity."""
        role_key = task_role.strip().lower()
        sev_upper = (severity or "").strip().upper()

        complexity = TaskComplexity.LOW
        if role_key in self.PRO_ROLES:
            complexity = TaskComplexity.HIGH
        elif role_key in self.PINNED_FLASH_ROLES:
            complexity = TaskComplexity.LOW
        elif sev_upper in {"P0", "SEV0"}:
            complexity = TaskComplexity.CRITICAL
        elif any(pat.search(prompt_text) for pat in _HIGH_COMPLEXITY_PATTERNS):
            complexity = TaskComplexity.HIGH
        elif sev_upper == "P1" or token_estimate > 3000:
            complexity = TaskComplexity.MEDIUM

        use_pro = complexity in {TaskComplexity.HIGH, TaskComplexity.CRITICAL}
        selected = self.pro_model if use_pro else self.flash_model
        tier = "pro" if use_pro else "flash"
        escalated = role_key in self.FLASH_ROLES and use_pro

        rationale = (
            f"Escalated '{role_key}' to Pro ({selected}) due to {complexity.value} complexity signals."
            if escalated
            else (
                f"Routed deep-reasoning role '{role_key}' to Pro ({selected})."
                if use_pro
                else f"Routed fast/structured role '{role_key}' to Flash ({selected}) for low latency."
            )
        )

        decision = ModelSelectionDecision(
            selected_model=selected,
            tier=tier,
            complexity=complexity,
            task_role=role_key,
            escalated=escalated,
            rationale=rationale,
        )
        self.logger.info(
            "routing.model.selected",
            task_role=role_key,
            selected_model=selected,
            tier=tier,
            complexity=complexity.value,
            escalated=escalated,
        )
        return decision

    def build_before_model_callback(self, *, task_role: str):
        """Creates an ADK ``before_model_callback`` performing dynamic model escalation."""

        def _dynamic_route_callback(
            callback_context: CallbackContext, llm_request: LlmRequest
        ) -> Optional[LlmResponse]:
            with traced_operation(
                "routing.dynamic_model_selection",
                attributes={"routing.task_role": task_role},
            ) as span:
                prompt_text = extract_text_from_contents(llm_request.contents)
                state: Any = getattr(callback_context, "state", None)
                has_state = state is not None and hasattr(state, "get")
                severity = state.get("incident_severity") if has_state else None
                decision = self.select_model(
                    task_role=task_role,
                    prompt_text=prompt_text,
                    severity=severity,
                )
                llm_request.model = decision.selected_model
                span.set_attribute("gen_ai.request.model", decision.selected_model)
                span.set_attribute("routing.tier", decision.tier)
                span.set_attribute("routing.escalated", decision.escalated)
                if has_state and hasattr(state, "__setitem__"):
                    state["last_model_routing_decision"] = decision.model_dump(mode="json")
                return None

        return _dynamic_route_callback
