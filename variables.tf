variable "project_id" {
  type        = string
  description = "Google Cloud Project ID where the GEAP Enterprise Ops Agent is deployed."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "Google Cloud region for Vertex AI Agent Engine, Artifact Registry, and Cloud SQL."
}

variable "app_name" {
  type        = string
  default     = "geap-ops-agent"
  description = "Short DNS-safe resource prefix for GCP resources."
}

variable "environment" {
  type        = string
  default     = "prod"
  description = "Deployment environment label (dev, staging, prod)."
}

variable "db_tier" {
  type        = string
  default     = "db-f1-micro"
  description = "Cloud SQL machine tier for persistent ADK session storage."
}

variable "gemini_api_key_secret_id" {
  type        = string
  default     = "gemini-api-key"
  description = "Secret Manager secret ID storing the Gemini API key (if Express Mode is used)."
}

variable "ops_db_url_secret_id" {
  type        = string
  default     = "ops-db-url"
  description = "Secret Manager secret ID storing the SQLAlchemy async database URL."
}

variable "pagerduty_webhook_secret_id" {
  type        = string
  default     = "pagerduty-webhook-secret"
  description = "Secret Manager secret ID storing the incident paging webhook token."
}
