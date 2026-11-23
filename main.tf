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

locals {
  required_apis = toset([
    "aiplatform.googleapis.com",
    "secretmanager.googleapis.com",
    "dlp.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "sqladmin.googleapis.com",
    "run.googleapis.com",
  ])

  runtime_sa_roles = toset([
    "roles/aiplatform.user",
    "roles/secretmanager.secretAccessor",
    "roles/dlp.user",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/cloudsql.client",
  ])
}

resource "google_project_service" "enabled_apis" {
  for_each           = local.required_apis
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Least-privilege runtime service account for Vertex AI Agent Engine
resource "google_service_account" "agent_runtime" {
  account_id   = "${var.app_name}-sa"
  display_name = "GEAP Enterprise Ops ADK Agent Runtime Service Account"
  description  = "Least-privilege service account for the GEAP Enterprise Ops multi-agent pipeline."
  depends_on   = [google_project_service.enabled_apis]
}

resource "google_project_iam_member" "agent_runtime_roles" {
  for_each = local.runtime_sa_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.agent_runtime.email}"
}

# Secret Manager containers (secret values are populated out-of-band, never in VCS)
resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = var.gemini_api_key_secret_id
  labels = {
    app = var.app_name
    env = var.environment
  }
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret" "ops_db_url" {
  secret_id = var.ops_db_url_secret_id
  labels = {
    app = var.app_name
    env = var.environment
  }
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret" "pagerduty_webhook_secret" {
  secret_id = var.pagerduty_webhook_secret_id
  labels = {
    app = var.app_name
    env = var.environment
  }
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret_iam_member" "gemini_key_accessor" {
  secret_id = google_secret_manager_secret.gemini_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agent_runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "ops_db_url_accessor" {
  secret_id = google_secret_manager_secret.ops_db_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agent_runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "pagerduty_accessor" {
  secret_id = google_secret_manager_secret.pagerduty_webhook_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agent_runtime.email}"
}

# Artifact Registry repository for CI/CD agent container builds
resource "google_artifact_registry_repository" "agent_repo" {
  location      = var.region
  repository_id = "${var.app_name}-repo"
  description   = "Container and package repository for ${var.app_name}."
  format        = "DOCKER"
  depends_on    = [google_project_service.enabled_apis]
}

# Uniform-access GCS staging bucket for ADK Agent Engine artifacts & eval reports
resource "google_storage_bucket" "agent_staging" {
  name                        = "${var.project_id}-${var.app_name}-staging"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = false

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.enabled_apis]
}

# Persistent Cloud SQL PostgreSQL instance backing ADK DatabaseSessionService
resource "google_sql_database_instance" "ops_sessions_db" {
  name                = "${var.app_name}-sessions-${var.environment}"
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = var.environment == "prod"

  settings {
    tier = var.db_tier
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"
    }
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_sql_database" "sessions_database" {
  name     = "adk_ops_sessions"
  instance = google_sql_database_instance.ops_sessions_db.name
}
