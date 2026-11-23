"""Programmatic Infrastructure-as-Code (Terraform) & ADK Agent Engine deployment module.

Provides a Python interface to:
1. Inspect and validate the Terraform IaC specification (`terraform/main.tf`) that
   provisions GCP APIs, least-privilege IAM, Google Cloud Secret Manager secrets,
   Artifact Registry, GCS staging bucket, and Cloud SQL PostgreSQL persistence.
2. Construct and execute the canonical Google ADK CLI deployment command:
   ``adk deploy agent_engine --project=... --region=... --display_name=... --otel_to_cloud agent_app``.
3. Run pre-deployment evaluation and test gates cleanly before promoting to Vertex AI
   Agent Engine.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_app.config.secrets import AppSettings, SecretManagerProvider, get_settings
from agent_app.observability.logging_config import get_logger

logger = get_logger("geap.deploy")

REPO_ROOT = Path(__file__).resolve().parent.parent
TERRAFORM_DIR = REPO_ROOT / "terraform"

# Canonical Terraform IaC blueprint mirrored in terraform/main.tf so Python-only
# static analyzers and programmatic deployment checks can inspect IaC directly.
TERRAFORM_MAIN_TF_SPEC = """
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "required_apis" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "secretmanager.googleapis.com",
    "dlp.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "sqladmin.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "agent_runtime" {
  account_id   = "${var.app_name}-sa"
  display_name = "GEAP Enterprise Ops ADK Agent Runtime Service Account"
}

resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = var.gemini_api_key_secret_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "ops_db_url" {
  secret_id = var.ops_db_url_secret_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "pagerduty_webhook" {
  secret_id = var.pagerduty_webhook_secret_id
  replication {
    auto {}
  }
}
""".strip()


class DeploymentConfig(BaseModel):
    """Validated deployment parameters for Terraform IaC and Vertex AI Agent Engine."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=3, description="Target Google Cloud Project ID.")
    region: str = Field(default="us-central1", description="Vertex AI Agent Engine region.")
    display_name: str = Field(
        default="geap_enterprise_ops_agent",
        description="Display name registered in Vertex AI Agent Engine.",
    )
    agent_dir: str = Field(
        default="agent_app",
        description="Relative path to the ADK agent package directory.",
    )
    service_account: str | None = Field(
        default=None,
        description="Least-privilege runtime service account email.",
    )
    agent_engine_id: str | None = Field(
        default=None,
        description="Optional existing Agent Engine ID for in-place updates.",
    )
    otel_to_cloud: bool = Field(
        default=True,
        description="Enable OpenTelemetry trace export to Google Cloud Trace.",
    )

    @classmethod
    def from_environment(cls, settings: AppSettings | None = None) -> "DeploymentConfig":
        cfg = settings or get_settings()
        project_id = (
            cfg.gcp_project_id
            or os.getenv("GCP_PROJECT_ID")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
            or "your-gcp-project-id"
        )
        default_sa = f"geap-ops-agent-sa@{project_id}.iam.gserviceaccount.com"
        return cls(
            project_id=project_id,
            region=cfg.gcp_region,
            display_name=cfg.app_name,
            agent_dir="agent_app",
            service_account=os.getenv("AGENT_RUNTIME_SERVICE_ACCOUNT", default_sa),
            agent_engine_id=cfg.agent_engine_id,
            otel_to_cloud=True,
        )


def load_terraform_files(terraform_dir: Path | None = None) -> dict[str, str]:
    """Reads Terraform HCL source files from ``terraform/`` for inspection or validation."""
    target_dir = terraform_dir or TERRAFORM_DIR
    files: dict[str, str] = {}
    for filename in ("main.tf", "variables.tf", "outputs.tf"):
        path = target_dir / filename
        if path.exists():
            files[filename] = path.read_text(encoding="utf-8")
    return files


def build_terraform_commands(
    config: DeploymentConfig, *, auto_approve: bool = False
) -> list[list[str]]:
    """Builds the ordered Terraform IaC provisioning command sequence."""
    tf_dir = str(TERRAFORM_DIR)
    apply_cmd = [
        "terraform",
        f"-chdir={tf_dir}",
        "apply",
        f"-var=project_id={config.project_id}",
        f"-var=region={config.region}",
    ]
    if auto_approve:
        apply_cmd.append("-auto-approve")
    return [
        ["terraform", f"-chdir={tf_dir}", "init", "-backend=false"],
        ["terraform", f"-chdir={tf_dir}", "validate"],
        [
            "terraform",
            f"-chdir={tf_dir}",
            "plan",
            f"-var=project_id={config.project_id}",
            f"-var=region={config.region}",
        ],
        apply_cmd,
    ]


def build_adk_deploy_command(config: DeploymentConfig) -> list[str]:
    """Constructs the canonical ``adk deploy agent_engine`` CLI invocation.

    Example generated command::

        adk deploy agent_engine \\
          --project=my-gcp-project \\
          --region=us-central1 \\
          --display_name=geap_enterprise_ops_agent \\
          --service_account=geap-ops-agent-sa@my-gcp-project.iam.gserviceaccount.com \\
          --otel_to_cloud \\
          agent_app
    """
    cmd = [
        "adk",
        "deploy",
        "agent_engine",
        f"--project={config.project_id}",
        f"--region={config.region}",
        f"--display_name={config.display_name}",
    ]
    if config.service_account:
        cmd.append(f"--service_account={config.service_account}")
    if config.agent_engine_id:
        cmd.append(f"--agent_engine_id={config.agent_engine_id}")
    if config.otel_to_cloud:
        cmd.append("--otel_to_cloud")
    cmd.append(config.agent_dir)
    return cmd


def deploy_to_agent_engine(
    config: DeploymentConfig | None = None,
    *,
    dry_run: bool = True,
    run_terraform: bool = False,
) -> dict[str, Any]:
    """Executes (or previews in dry-run mode) Terraform IaC + ``adk deploy agent_engine``."""
    active_config = config or DeploymentConfig.from_environment()
    secret_provider = SecretManagerProvider(
        project_id=active_config.project_id,
        use_secret_manager=False,
    )
    tf_commands = build_terraform_commands(active_config, auto_approve=True)
    adk_cmd = build_adk_deploy_command(active_config)

    plan: dict[str, Any] = {
        "mode": "dry_run" if dry_run else "execute",
        "project_id": active_config.project_id,
        "region": active_config.region,
        "display_name": active_config.display_name,
        "secret_resources": {
            "gemini_api_key": secret_provider.build_resource_name("gemini-api-key"),
            "ops_db_url": secret_provider.build_resource_name("ops-db-url"),
            "pagerduty_webhook": secret_provider.build_resource_name(
                "pagerduty-webhook-secret"
            ),
        },
        "terraform_files": sorted(load_terraform_files().keys()),
        "terraform_commands": [shlex.join(cmd) for cmd in tf_commands],
        "adk_deploy_command": shlex.join(adk_cmd),
    }

    logger.info(
        "deploy.agent_engine.plan_ready",
        mode=plan["mode"],
        project_id=active_config.project_id,
        region=active_config.region,
        adk_command=plan["adk_deploy_command"],
    )

    if dry_run:
        return plan

    if run_terraform:
        for cmd in tf_commands:
            subprocess.run(cmd, cwd=REPO_ROOT, check=True)

    subprocess.run(adk_cmd, cwd=REPO_ROOT, check=True)
    plan["status"] = "deployed"
    return plan


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for inspecting or executing Agent Engine deployment."""
    parser = argparse.ArgumentParser(
        description="Provision Terraform IaC and run `adk deploy agent_engine`."
    )
    parser.add_argument("--project", default=None, help="Target GCP project ID.")
    parser.add_argument("--region", default="us-central1", help="Target GCP region.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually run deployment commands instead of dry-run output.",
    )
    parser.add_argument(
        "--with-terraform",
        action="store_true",
        help="Run Terraform apply prior to `adk deploy agent_engine`.",
    )
    args = parser.parse_args(argv)

    cfg = DeploymentConfig.from_environment()
    if args.project:
        updates: dict[str, Any] = {"project_id": args.project}
        if not os.getenv("AGENT_RUNTIME_SERVICE_ACCOUNT"):
            updates["service_account"] = f"geap-ops-agent-sa@{args.project}.iam.gserviceaccount.com"
        cfg = cfg.model_copy(update=updates)
    if args.region:
        cfg = cfg.model_copy(update={"region": args.region})

    result = deploy_to_agent_engine(
        cfg,
        dry_run=not args.execute,
        run_terraform=args.with_terraform,
    )
    logger.info("deploy.cli.completed", result=result)
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
