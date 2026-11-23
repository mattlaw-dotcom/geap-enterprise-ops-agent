output "agent_runtime_service_account" {
  description = "Least-privilege service account email passed to `adk deploy agent_engine --service_account`."
  value       = google_service_account.agent_runtime.email
}

output "staging_bucket_url" {
  description = "GCS bucket URL for ADK staging artifacts and evaluation results."
  value       = google_storage_bucket.agent_staging.url
}

output "artifact_registry_repository" {
  description = "Artifact Registry repository name."
  value       = google_artifact_registry_repository.agent_repo.name
}

output "sessions_db_connection_name" {
  description = "Cloud SQL connection name backing ADK DatabaseSessionService."
  value       = google_sql_database_instance.ops_sessions_db.connection_name
}

output "secret_manager_ids" {
  description = "Provisioned Google Cloud Secret Manager secret resource names."
  value = {
    gemini_api_key    = google_secret_manager_secret.gemini_api_key.id
    ops_db_url        = google_secret_manager_secret.ops_db_url.id
    pagerduty_webhook = google_secret_manager_secret.pagerduty_webhook_secret.id
  }
}
