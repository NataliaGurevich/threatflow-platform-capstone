variable "name_prefix" {
  description = "Name prefix for the Terraform-managed Gold runtime."
  type        = string
}

variable "aws_region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "silver_bucket_name" {
  type = string
}

variable "silver_bucket_arn" {
  type = string
}

variable "silver_prefix" {
  type    = string
  default = "silver"
}

variable "gold_bucket_name" {
  type = string
}

variable "gold_prefix" {
  type    = string
  default = "gold"
}

variable "catalog_database" {
  description = "Glue Catalog database containing the Gold external tables."
  type        = string
  default     = "threatflow_gold"
}

variable "script_s3_uri" {
  description = "Immutable S3 URI of the Glue Python entrypoint."
  type        = string

  validation {
    condition     = var.script_s3_uri == "" || can(regex("^s3://[^/]+/_artifacts/glue/releases/[^/]+/vulnerability_priority_job\\.py$", var.script_s3_uri))
    error_message = "script_s3_uri must reference vulnerability_priority_job.py under an immutable release prefix."
  }
}

variable "wheel_s3_uri" {
  description = "Immutable S3 URI of the ThreatFlow wheel used by Glue."
  type        = string

  validation {
    condition     = var.wheel_s3_uri == "" || can(regex("^s3://[^/]+/_artifacts/glue/releases/[^/]+/threatflow-[^/]+\\.whl$", var.wheel_s3_uri))
    error_message = "wheel_s3_uri must reference a ThreatFlow wheel under an immutable release prefix."
  }
}

variable "snapshot_type" {
  type    = string
  default = "RECONSTRUCTED"

  validation {
    condition     = contains(["OBSERVED", "RECONSTRUCTED"], var.snapshot_type)
    error_message = "snapshot_type must be OBSERVED or RECONSTRUCTED."
  }
}

variable "nvd_history_complete" {
  type    = bool
  default = false
}

variable "max_input_lag_days" {
  type    = number
  default = 2

  validation {
    condition     = var.max_input_lag_days >= 0 && floor(var.max_input_lag_days) == var.max_input_lag_days
    error_message = "max_input_lag_days must be a non-negative integer."
  }
}

variable "schedule_expression" {
  type    = string
  default = "cron(0 9 * * ? *)"
}

variable "schedule_timezone" {
  type    = string
  default = "Europe/Berlin"
}

variable "schedule_enabled" {
  description = "Enable only after a successful manual AUTO smoke test."
  type        = bool
  default     = false
}

variable "worker_type" {
  type    = string
  default = "G.1X"
}

variable "number_of_workers" {
  type    = number
  default = 2
}

variable "timeout_minutes" {
  type    = number
  default = 30
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "tags" {
  type    = map(string)
  default = {}
}
