"""Category 5 Tests: Golden Evals, Secret Manager, Terraform IaC, deploy.py, CI/CD, Secret Scan."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from google.adk.evaluation.eval_set import EvalSet

from agent_app.config.secrets import SecretManagerProvider, SecretResolutionError
from agent_app.deploy import (
    REPO_ROOT,
    TERRAFORM_MAIN_TF_SPEC,
    DeploymentConfig,
    build_adk_deploy_command,
    deploy_to_agent_engine,
    load_terraform_files,
)
from evals.run_evals import run_golden_evalset


@pytest.mark.asyncio
async def test_golden_evalset_validates_adk_schema_and_passes_100_percent() -> None:
    evalset_path = REPO_ROOT / "evals" / "golden_evalset.json"
    assert evalset_path.exists()

    parsed = EvalSet.model_validate(json.loads(evalset_path.read_text(encoding="utf-8")))
    assert len(parsed.eval_cases) >= 6

    summary = await run_golden_evalset(evalset_path, min_pass_rate=1.0)
    assert summary["gate_passed"] is True
    assert summary["pass_rate"] == 1.0
    assert summary["passed_cases"] == summary["total_cases"]


def test_secret_manager_provider_resolution_and_env_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _MockSecretClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def access_secret_version(self, *, request: dict[str, Any]) -> Any:
            self.calls.append(request["name"])
            return SimpleNamespace(payload=SimpleNamespace(data=b"resolved-from-gsm"))

    mock_client = _MockSecretClient()
    gsm_provider = SecretManagerProvider(
        project_id="enterprise-prod-123",
        use_secret_manager=True,
        client=mock_client,
    )
    first = gsm_provider.get_secret("gemini-api-key", env_var="GOOGLE_API_KEY", required=True)
    second = gsm_provider.get_secret("gemini-api-key", env_var="GOOGLE_API_KEY", required=True)
    assert first == "resolved-from-gsm"
    assert second == "resolved-from-gsm"
    assert mock_client.calls == [
        "projects/enterprise-prod-123/secrets/gemini-api-key/versions/latest"
    ]

    # Env fallback when Secret Manager is disabled locally
    monkeypatch.setenv("LOCAL_TEST_SECRET_VAR", "local-env-value")
    local_provider = SecretManagerProvider(use_secret_manager=False)
    assert (
        local_provider.get_secret("unused-id", env_var="LOCAL_TEST_SECRET_VAR", required=True)
        == "local-env-value"
    )

    with pytest.raises(SecretResolutionError):
        local_provider.get_secret("missing-id", env_var="NON_EXISTENT_ENV_VAR_XYZ", required=True)


def test_python_deploy_module_exposes_terraform_iac_and_adk_deploy_agent_engine() -> None:
    assert 'resource "google_secret_manager_secret"' in TERRAFORM_MAIN_TF_SPEC
    assert 'resource "google_service_account"' in TERRAFORM_MAIN_TF_SPEC

    tf_files = load_terraform_files()
    assert set(tf_files.keys()) == {"main.tf", "variables.tf", "outputs.tf"}
    assert "google_sql_database_instance" in tf_files["main.tf"]
    assert "google_secret_manager_secret" in tf_files["main.tf"]

    cfg = DeploymentConfig(
        project_id="my-enterprise-gcp",
        region="us-central1",
        display_name="geap_enterprise_ops_agent",
        service_account="geap-ops-agent-sa@my-enterprise-gcp.iam.gserviceaccount.com",
    )
    cmd = build_adk_deploy_command(cfg)
    assert cmd[:3] == ["adk", "deploy", "agent_engine"]
    assert "--project=my-enterprise-gcp" in cmd
    assert "--region=us-central1" in cmd
    assert "--otel_to_cloud" in cmd
    assert cmd[-1] == "agent_app"

    dry_plan = deploy_to_agent_engine(cfg, dry_run=True)
    assert dry_plan["mode"] == "dry_run"
    assert "adk deploy agent_engine" in dry_plan["adk_deploy_command"]
    assert "projects/my-enterprise-gcp/secrets/gemini-api-key/versions/latest" in (
        dry_plan["secret_resources"]["gemini_api_key"]
    )


def test_cicd_and_deploy_artifacts_are_present_and_valid() -> None:
    deploy_sh = REPO_ROOT / "deploy.sh"
    cloudbuild = REPO_ROOT / "cloudbuild.yaml"
    gh_ci = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    readme = REPO_ROOT / "README.md"

    assert deploy_sh.exists()
    assert "adk deploy agent_engine" in deploy_sh.read_text(encoding="utf-8")
    assert "terraform" in deploy_sh.read_text(encoding="utf-8")

    cb_doc = yaml.safe_load(cloudbuild.read_text(encoding="utf-8"))
    assert "steps" in cb_doc and "availableSecrets" in cb_doc
    assert "adk deploy agent_engine" in cloudbuild.read_text(encoding="utf-8")

    ci_doc = yaml.safe_load(gh_ci.read_text(encoding="utf-8"))
    assert "jobs" in ci_doc
    assert "lint-test-and-eval" in ci_doc["jobs"]
    assert "terraform-validate" in ci_doc["jobs"]

    readme_text = readme.read_text(encoding="utf-8")
    for heading in (
        "Tool & Interface Design",
        "Context & Memory",
        "Orchestration & Logic",
        "Observability & Tracing",
        "Infrastructure & CI/CD",
    ):
        assert heading in readme_text


def test_repository_contains_zero_hardcoded_secrets() -> None:
    """Scans all source and config files (excluding redaction test fixtures) for leaked keys."""
    secret_patterns = [
        re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bsk_(?:live|test|prod)_[A-Za-z0-9]{16,}\b"),
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ]
    exempt_files = {
        "test_observability_and_pii.py",
        "golden_evalset.json",
    }
    scan_roots = [
        REPO_ROOT / "agent_app",
        REPO_ROOT / "terraform",
        REPO_ROOT / ".github",
        REPO_ROOT / "deploy.sh",
        REPO_ROOT / "cloudbuild.yaml",
        REPO_ROOT / ".env.example",
    ]

    files_to_scan: list[Path] = []
    for root in scan_roots:
        if root.is_file():
            files_to_scan.append(root)
        elif root.is_dir():
            files_to_scan.extend(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts)

    leaks: list[str] = []
    for path in files_to_scan:
        if path.name in exempt_files:
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        for pat in secret_patterns:
            if pat.search(content):
                leaks.append(f"{path.relative_to(REPO_ROOT)} matched {pat.pattern}")

    assert leaks == [], f"Potential hardcoded secret(s) detected: {leaks}"
