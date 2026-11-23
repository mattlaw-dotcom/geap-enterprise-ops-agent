"""Automated Golden Dataset Evaluation Harness for GEAP Enterprise Ops Agent.

Validates ``evals/golden_evalset.json`` against Google ADK's ``EvalSet`` schema
and executes deterministic regression evaluations across all golden scenarios:
- Tool call trajectory & Pydantic output schema validation
- Flash vs. Pro strategic model routing accuracy
- Human-in-the-Loop (HITL) pause enforcement for high-stakes rollbacks
- Prompt-injection guardrail interception (``before_model_callback``)
- End-to-end PII & secret scrubbing across tool inputs and persisted tickets
- Guided error handling with explicit recovery instructions

Supports ``--live`` to invoke Google ADK's live ``adk eval`` CLI when GCP/Gemini
credentials are configured.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from google.adk.evaluation.eval_set import EvalSet
from google.adk.models.llm_request import LlmRequest
from google.genai import types

from agent_app.guardrails.hitl import HumanApprovalGate
from agent_app.guardrails.policy_plugin import EnterprisePolicyGuardrailPlugin
from agent_app.observability.pii_redactor import PIIRedactor
from agent_app.routing import ModelRouter
from agent_app.tools.ops_tools import (
    create_critical_incident_ticket,
    execute_production_service_rollback,
    fetch_service_health_metrics,
    schedule_maintenance_window,
    search_incident_runbooks,
)

TOOL_DISPATCH = {
    "fetch_service_health_metrics": fetch_service_health_metrics,
    "search_incident_runbooks": search_incident_runbooks,
    "create_critical_incident_ticket": create_critical_incident_ticket,
    "execute_production_service_rollback": execute_production_service_rollback,
    "schedule_maintenance_window": schedule_maintenance_window,
}


@dataclass
class CaseEvaluationResult:
    """Outcome for a single golden evaluation case."""

    eval_id: str
    category: str
    passed: bool
    score: float
    details: str


class _MinimalCallbackContext:
    def __init__(self, agent_name: str = "intake_triage_agent") -> None:
        self.agent_name = agent_name
        self.invocation_id = "eval-invocation"
        self.state: dict[str, Any] = {}


async def evaluate_case(
    case: Any,
    *,
    router: ModelRouter,
    guardrail: EnterprisePolicyGuardrailPlugin,
    redactor: PIIRedactor,
) -> CaseEvaluationResult:
    """Executes deterministic offline verification for one ADK EvalCase."""
    expected = dict(case.final_session_state or {})
    category = str(expected.get("expected_category", "general"))
    invocation = case.conversation[0]
    prompt_text = "\n".join(
        p.text for p in (invocation.user_content.parts or []) if getattr(p, "text", None)
    )
    tool_uses = list(invocation.intermediate_data.tool_uses or [])

    if category == "guardrail_block":
        req = LlmRequest(
            model=router.flash_model,
            contents=[types.Content(role="user", parts=[types.Part.from_text(text=prompt_text)])],
        )
        blocked_resp = await guardrail.before_model_callback(
            callback_context=_MinimalCallbackContext(),  # type: ignore[arg-type]
            llm_request=req,
        )
        passed = blocked_resp is not None
        return CaseEvaluationResult(
            eval_id=case.eval_id,
            category=category,
            passed=passed,
            score=1.0 if passed else 0.0,
            details="Prompt injection intercepted before LLM invocation."
            if passed
            else "Guardrail failed to intercept prompt injection.",
        )

    outputs: list[dict[str, Any]] = []
    for call in tool_uses:
        fn = TOOL_DISPATCH.get(call.name or "")
        if fn is None:
            return CaseEvaluationResult(
                eval_id=case.eval_id,
                category=category,
                passed=False,
                score=0.0,
                details=f"Unknown tool in trajectory: {call.name}",
            )
        outputs.append(fn(**dict(call.args or {})))

    if category == "happy_path_triage":
        health = outputs[0]
        runbooks = outputs[1]
        decision = router.select_model(task_role="intake_triage", prompt_text=prompt_text)
        passed = (
            health.get("status") == "ok"
            and health.get("health_state") == expected["expected_health_state"]
            and runbooks.get("status") == "ok"
            and any(rb["runbook_id"] == expected["expected_runbook_id"] for rb in runbooks["runbooks"])
            and decision.tier == expected["expected_model_tier"]
        )
        return CaseEvaluationResult(
            eval_id=case.eval_id,
            category=category,
            passed=passed,
            score=1.0 if passed else 0.0,
            details=f"health={health.get('health_state')}, model_tier={decision.tier}",
        )

    if category == "incident_ticketing":
        health, runbooks, ticket = outputs[0], outputs[1], outputs[2]
        decision = router.select_model(
            task_role="remediation_planner", prompt_text=prompt_text, severity="P0"
        )
        passed = (
            health.get("health_state") == expected["expected_health_state"]
            and ticket.get("status") == "ok"
            and str(ticket.get("ticket_id", "")).startswith("INC-")
            and decision.tier == expected["expected_model_tier"]
        )
        return CaseEvaluationResult(
            eval_id=case.eval_id,
            category=category,
            passed=passed,
            score=1.0 if passed else 0.0,
            details=f"ticket_id={ticket.get('ticket_id')}, model_tier={decision.tier}",
        )

    if category == "hitl_gate":
        rollback_resp = outputs[0]
        decision = router.select_model(task_role="intake_triage", prompt_text=prompt_text)
        passed = (
            rollback_resp.get("status") == expected["expected_status"]
            and str(rollback_resp.get("approval_id", "")).startswith("APR-")
            and decision.tier == expected["expected_model_tier"]
        )
        return CaseEvaluationResult(
            eval_id=case.eval_id,
            category=category,
            passed=passed,
            score=1.0 if passed else 0.0,
            details=f"status={rollback_resp.get('status')}, approval_id={rollback_resp.get('approval_id')}",
        )

    if category == "pii_redaction":
        ticket_resp = outputs[0]
        serialized = json.dumps(ticket_resp)
        redacted_prompt = redactor.redact_text(prompt_text)
        forbidden = expected.get("forbidden_substrings", [])
        leaked = [s for s in forbidden if s in serialized or s in redacted_prompt]
        passed = ticket_resp.get("status") == "ok" and not leaked
        return CaseEvaluationResult(
            eval_id=case.eval_id,
            category=category,
            passed=passed,
            score=1.0 if passed else 0.0,
            details="All PII/secrets scrubbed cleanly." if passed else f"Leaked: {leaked}",
        )

    if category == "guided_error_recovery":
        err_resp = outputs[0]
        passed = (
            err_resp.get("status") == "error"
            and err_resp.get("error_code") == expected["expected_error_code"]
            and bool(err_resp.get("recovery_instructions"))
            and bool(err_resp.get("allowed_values"))
        )
        return CaseEvaluationResult(
            eval_id=case.eval_id,
            category=category,
            passed=passed,
            score=1.0 if passed else 0.0,
            details=f"error_code={err_resp.get('error_code')}, retryable={err_resp.get('retryable')}",
        )

    return CaseEvaluationResult(
        eval_id=case.eval_id,
        category=category,
        passed=False,
        score=0.0,
        details=f"Unhandled evaluation category: {category}",
    )


async def run_golden_evalset(
    evalset_path: Path,
    *,
    min_pass_rate: float = 1.0,
) -> dict[str, Any]:
    """Loads, validates, and evaluates all cases in an ADK ``EvalSet`` JSON file."""
    raw = json.loads(evalset_path.read_text(encoding="utf-8"))
    eval_set = EvalSet.model_validate(raw)

    router = ModelRouter()
    redactor = PIIRedactor(enable_cloud_dlp=False)
    hitl_gate = HumanApprovalGate(redactor=redactor)
    guardrail = EnterprisePolicyGuardrailPlugin(hitl_gate=hitl_gate, redactor=redactor)

    results: list[CaseEvaluationResult] = []
    # Run with an isolated temp knowledge DB so evaluations leave no workspace artifacts.
    with tempfile.TemporaryDirectory() as tmp_dir:
        import os

        prev_db = os.environ.get("OPS_KNOWLEDGE_DB_PATH")
        os.environ["OPS_KNOWLEDGE_DB_PATH"] = str(Path(tmp_dir) / "eval_knowledge.db")
        try:
            for case in eval_set.eval_cases:
                res = await evaluate_case(
                    case,
                    router=router,
                    guardrail=guardrail,
                    redactor=redactor,
                )
                results.append(res)
        finally:
            if prev_db is None:
                os.environ.pop("OPS_KNOWLEDGE_DB_PATH", None)
            else:
                os.environ["OPS_KNOWLEDGE_DB_PATH"] = prev_db

    passed_count = sum(1 for r in results if r.passed)
    total = len(results)
    pass_rate = (passed_count / total) if total else 0.0

    return {
        "eval_set_id": eval_set.eval_set_id,
        "total_cases": total,
        "passed_cases": passed_count,
        "pass_rate": round(pass_rate, 4),
        "threshold": min_pass_rate,
        "gate_passed": pass_rate >= min_pass_rate,
        "results": [asdict(r) for r in results],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run GEAP Enterprise Ops golden dataset regression evaluations."
    )
    parser.add_argument(
        "--evalset",
        type=Path,
        default=REPO_ROOT / "evals" / "golden_evalset.json",
        help="Path to ADK EvalSet JSON file.",
    )
    parser.add_argument(
        "--min-pass-rate",
        type=float,
        default=1.0,
        help="Minimum fraction of passing cases required to succeed (0.0-1.0).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Also invoke live `adk eval agent_app <evalset>` against Gemini API.",
    )
    args = parser.parse_args(argv)

    summary = asyncio.run(
        run_golden_evalset(args.evalset, min_pass_rate=args.min_pass_rate)
    )
    print(json.dumps(summary, indent=2))

    if not summary["gate_passed"]:
        return 1

    if args.live:
        subprocess.run(
            ["adk", "eval", "agent_app", str(args.evalset)],
            cwd=REPO_ROOT,
            check=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
