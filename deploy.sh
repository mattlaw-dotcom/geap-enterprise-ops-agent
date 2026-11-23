#!/usr/bin/env bash
# End-to-end IaC provisioning, verification, and Vertex AI Agent Engine deployment script.
set -euo pipefail

GCP_PROJECT_ID="${GCP_PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-}}"
GCP_REGION="${GCP_REGION:-us-central1}"
ADK_APP_NAME="${ADK_APP_NAME:-geap_enterprise_ops_agent}"
SKIP_TERRAFORM="${SKIP_TERRAFORM:-false}"
DRY_RUN="${DRY_RUN:-false}"

if [[ -z "${GCP_PROJECT_ID}" ]]; then
  echo "ERROR: GCP_PROJECT_ID (or GOOGLE_CLOUD_PROJECT) must be set." >&2
  exit 1
fi

echo "==> [1/4] Running automated unit tests (pytest -v)..."
pytest -v

echo "==> [2/4] Running golden dataset evaluation harness..."
python3 evals/run_evals.py --evalset evals/golden_evalset.json

if [[ "${SKIP_TERRAFORM}" != "true" ]]; then
  echo "==> [3/4] Provisioning GCP infrastructure via Terraform..."
  terraform -chdir=terraform init
  terraform -chdir=terraform validate
  if [[ "${DRY_RUN}" == "true" ]]; then
    terraform -chdir=terraform plan \
      -var="project_id=${GCP_PROJECT_ID}" \
      -var="region=${GCP_REGION}"
  else
    terraform -chdir=terraform apply -auto-approve \
      -var="project_id=${GCP_PROJECT_ID}" \
      -var="region=${GCP_REGION}"
  fi
fi

RUNTIME_SA="${AGENT_RUNTIME_SERVICE_ACCOUNT:-geap-ops-agent-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com}"

echo "==> [4/4] Deploying multi-agent ADK app to Vertex AI Agent Engine..."
DEPLOY_CMD=(
  adk deploy agent_engine
  "--project=${GCP_PROJECT_ID}"
  "--region=${GCP_REGION}"
  "--display_name=${ADK_APP_NAME}"
  "--service_account=${RUNTIME_SA}"
  "--otel_to_cloud"
  agent_app
)

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY_RUN] Would execute: ${DEPLOY_CMD[*]}"
  python3 -m agent_app.deploy --project="${GCP_PROJECT_ID}" --region="${GCP_REGION}"
else
  "${DEPLOY_CMD[@]}"
fi
