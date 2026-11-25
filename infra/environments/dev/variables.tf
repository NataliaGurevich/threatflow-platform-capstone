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

variable "epss_silver_lambda_function_name" {
  description = "Name of the EPSS Bronze-to-Silver Lambda function."
  type        = string
  default     = "threatflow-epss-silver-dev"
}

variable "epss_silver_lambda_execution_role_name" {
  description = "Name of the dedicated EPSS Silver Lambda execution role."
  type        = string
  default     = "threatflow-epss-silver-dev-execution"
}

variable "epss_silver_lambda_image_uri" {
  description = "Immutable ECR image URI for the EPSS Silver Lambda, addressed by digest."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.epss_silver_lambda_image_uri))
    error_message = "epss_silver_lambda_image_uri must end in @sha256:<64 lowercase hex characters>."
  }
}

variable "epss_silver_lambda_memory_size_mb" {
  description = "Memory allocated to the PyArrow EPSS Silver Lambda."
  type        = number
  default     = 2048
}

variable "epss_silver_lambda_timeout_seconds" {
  description = "Maximum EPSS Silver Lambda execution time."
  type        = number
  default     = 300
}

variable "epss_silver_lambda_reserved_concurrency" {
  description = "Reserved concurrency for the development Lambda; -1 uses the shared account pool."
  type        = number
  default     = -1
}

variable "epss_silver_lambda_log_retention_days" {
  description = "Retention period for EPSS Silver Lambda CloudWatch logs."
  type        = number
  default     = 30
}

variable "epss_silver_event_source_mapping_enabled" {
  description = "Enable Lambda polling of the EPSS SQS event queue."
  type        = bool
  default     = true
}

variable "epss_silver_event_source_maximum_concurrency" {
  description = "Maximum concurrent Lambda invocations started by the EPSS SQS mapping."
  type        = number
  default     = 2
}

variable "epss_minimum_count_overrides" {
  description = "Investigated EPSS date exceptions; empty by default and applied to ingestion and Silver."
  type        = map(number)
  default     = {}

  validation {
    condition = alltrue([
      for score_date, count in var.epss_minimum_count_overrides :
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", score_date)) && count >= 1 && floor(count) == count
    ])
    error_message = "epss_minimum_count_overrides must map ISO dates to positive integer counts."
  }
}

variable "cisa_silver_lambda_image_uri" {
  description = "Immutable ECR image URI for the CISA Silver Lambda."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.cisa_silver_lambda_image_uri))
    error_message = "cisa_silver_lambda_image_uri must end in @sha256:<64 lowercase hex characters>."
  }
}

variable "cisa_silver_event_source_mapping_enabled" {
  description = "Enable CISA SQS polling after direct-invoke verification."
  type        = bool
  default     = false
}

variable "cisa_minimum_record_count" {
  description = "Absolute fail-closed floor for incremental CISA catalogs."
  type        = number
  default     = 100
}

variable "cisa_minimum_previous_ratio" {
  description = "Minimum ratio to the latest committed CISA snapshot count."
  type        = number
  default     = 0.8
}

variable "nvd_silver_lambda_image_uri" {
  description = "Immutable NVD Silver Lambda image URI addressed by digest."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.nvd_silver_lambda_image_uri))
    error_message = "nvd_silver_lambda_image_uri must end in @sha256:<64 lowercase hex characters>."
  }
}

variable "nvd_silver_event_source_mapping_enabled" {
  description = "Enable Lambda polling of the NVD committed-window queue."
  type        = bool
  default     = false
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

variable "create_gold_daily_runtime" {
  description = "Create a separate Terraform-managed daily Gold Glue runtime."
  type        = bool
  default     = false
}

variable "gold_bucket_name" {
  description = "Existing S3 bucket receiving Gold datasets."
  type        = string
  default     = ""
}

variable "gold_prefix" {
  description = "Key prefix reserved for Gold datasets and Glue temporary files."
  type        = string
  default     = "gold"
}

variable "gold_glue_script_s3_uri" {
  description = "Immutable S3 URI of the daily Gold Glue entrypoint."
  type        = string
  default     = ""
}

variable "gold_glue_wheel_s3_uri" {
  description = "Immutable S3 URI of the daily Gold ThreatFlow wheel."
  type        = string
  default     = ""
}

variable "gold_catalog_database" {
  description = "Glue Catalog database for Gold Athena tables."
  type        = string
  default     = "threatflow_gold"
}

variable "gold_max_input_lag_days" {
  description = "Maximum age of the AUTO-selected EPSS snapshot relative to yesterday UTC."
  type        = number
  default     = 2
}

variable "gold_schedule_expression" {
  description = "EventBridge Scheduler expression for daily Gold creation."
  type        = string
  default     = "cron(0 9 * * ? *)"
}

variable "gold_schedule_timezone" {
  description = "IANA timezone used by the Gold schedule."
  type        = string
  default     = "Europe/Berlin"
}

variable "gold_schedule_enabled" {
  description = "Enable only after a successful manual AUTO Glue smoke test."
  type        = bool
  default     = false
}

variable "gold_alert_email" {
  description = "Optional email recipient for Gold Glue failure, Scheduler DLQ, and missing-success alarms. Confirmation is required after apply."
  type        = string
  default     = ""

  validation {
    condition     = var.gold_alert_email == "" || can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.gold_alert_email))
    error_message = "gold_alert_email must be empty or a syntactically valid email address."
  }
}

variable "gold_success_heartbeat_hours" {
  description = "Maximum hours without a successful daily Gold Glue run before alerting."
  type        = number
  default     = 26

  validation {
    condition     = var.gold_success_heartbeat_hours >= 24 && var.gold_success_heartbeat_hours <= 72 && floor(var.gold_success_heartbeat_hours) == var.gold_success_heartbeat_hours
    error_message = "gold_success_heartbeat_hours must be a whole number between 24 and 72."
  }
}

variable "create_athena_metabase_serving" {
  description = "Create the bounded Athena workgroup, query-results bucket, and Metabase service account."
  type        = bool
  default     = false
}

variable "athena_results_bucket_name" {
  description = "Globally unique bucket for disposable Athena query results."
  type        = string
  default     = ""
}

variable "athena_results_retention_days" {
  type    = number
  default = 7
}

variable "athena_metabase_workgroup_name" {
  type    = string
  default = "threatflow-metabase-dev"
}

variable "athena_metabase_bytes_scanned_cutoff_per_query" {
  description = "Maximum bytes one Metabase query may scan."
  type        = number
  default     = 1000000000
}

variable "athena_metabase_user_name" {
  description = "IAM service account used by local Metabase; Terraform does not create access keys."
  type        = string
  default     = "threatflow-metabase-athena-dev"
}
