variable "aws_region" {
  description = "AWS region for the ThreatFlow development environment."
  type        = string
  default     = "eu-central-1"
}

variable "bucket_name" {
  description = "Globally unique name for the ThreatFlow development Bronze bucket."
  type        = string
}

variable "bronze_prefix" {
  description = "Key prefix reserved for Bronze artifacts."
  type        = string
  default     = "bronze"
}

variable "noncurrent_version_retention_days" {
  description = "Days to retain superseded object versions for recovery."
  type        = number
  default     = 90
}

variable "silver_bucket_name" {
  description = "Globally unique name for the ThreatFlow development Silver bucket."
  type        = string
}

variable "silver_prefix" {
  description = "Key prefix reserved for Silver datasets."
  type        = string
  default     = "silver"
}

variable "silver_noncurrent_version_retention_days" {
  description = "Days to retain superseded Silver object versions for recovery."
  type        = number
  default     = 30
}

variable "create_airflow_local_identity" {
  description = "Create the local-only IAM user used by Airflow through temporary aws login credentials."
  type        = bool
  default     = false
}

variable "airflow_local_user_name" {
  description = "IAM user name for local Airflow development; no access keys are created."
  type        = string
  default     = "threatflow-airflow-local"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.airflow_local_user_name))
    error_message = "airflow_local_user_name must be a valid IAM user name."
  }
}
