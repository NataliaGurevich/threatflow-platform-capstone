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

variable "epss_silver_queue_name" {
  description = "Name of the Standard queue receiving EPSS Bronze object events."
  type        = string
  default     = "threatflow-epss-bronze-events-dev"
}

variable "epss_silver_dlq_name" {
  description = "Name of the DLQ for failed EPSS Bronze-to-Silver transformations."
  type        = string
  default     = "threatflow-epss-bronze-events-dev-dlq"
}

variable "epss_silver_queue_visibility_timeout_seconds" {
  description = "SQS visibility timeout; 1800 seconds supports a future Lambda timeout up to 300 seconds."
  type        = number
  default     = 1800
}

variable "epss_silver_queue_message_retention_seconds" {
  description = "Retention for unprocessed EPSS Bronze event messages."
  type        = number
  default     = 345600
}

variable "epss_silver_dlq_message_retention_seconds" {
  description = "Retention for failed EPSS Bronze event messages."
  type        = number
  default     = 1209600
}

variable "epss_silver_queue_max_receive_count" {
  description = "Failed receives before an EPSS event moves to the DLQ."
  type        = number
  default     = 5
}

variable "epss_silver_image_repository_name" {
  description = "Private ECR repository for the EPSS Silver Lambda container image."
  type        = string
  default     = "threatflow/epss-silver"
}

variable "epss_silver_image_untagged_retention_days" {
  description = "Days to retain untagged EPSS Silver container images."
  type        = number
  default     = 7
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
