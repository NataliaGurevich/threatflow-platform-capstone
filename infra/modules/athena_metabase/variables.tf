variable "aws_region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "results_bucket_name" {
  description = "Globally unique S3 bucket name for Athena query results."
  type        = string
}

variable "results_prefix" {
  type    = string
  default = "metabase/"

  validation {
    condition     = endswith(var.results_prefix, "/") && !startswith(var.results_prefix, "/")
    error_message = "results_prefix must end with a slash and must not start with a slash."
  }
}

variable "results_retention_days" {
  description = "Days to retain disposable Athena result objects."
  type        = number
  default     = 7

  validation {
    condition     = var.results_retention_days >= 1
    error_message = "results_retention_days must be at least one day."
  }
}

variable "workgroup_name" {
  type    = string
  default = "threatflow-metabase-dev"
}

variable "bytes_scanned_cutoff_per_query" {
  description = "Maximum bytes one Metabase Athena query may scan."
  type        = number
  default     = 1000000000

  validation {
    condition     = var.bytes_scanned_cutoff_per_query >= 10000000
    error_message = "Athena requires a cutoff of at least 10,000,000 bytes."
  }
}

variable "metabase_user_name" {
  description = "IAM service-account user; access keys are deliberately not managed by Terraform."
  type        = string
  default     = "threatflow-metabase-athena-dev"
}

variable "gold_bucket_name" {
  type = string
}

variable "gold_prefix" {
  type    = string
  default = "gold"
}

variable "catalog_database" {
  type    = string
  default = "threatflow_gold"
}

variable "tags" {
  type    = map(string)
  default = {}
}
