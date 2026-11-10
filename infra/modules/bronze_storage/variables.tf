variable "bucket_name" {
  description = "Globally unique name for the ThreatFlow Bronze S3 bucket."
  type        = string

  validation {
    condition = (
      length(var.bucket_name) >= 3 &&
      length(var.bucket_name) <= 33 &&
      can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.bucket_name)) &&
      !strcontains(var.bucket_name, "..")
    )
    error_message = "bucket_name must satisfy the basic lowercase S3 naming constraints."
  }
}

variable "bronze_prefix" {
  description = "Key prefix reserved for immutable Bronze artifacts."
  type        = string
  default     = "bronze"

  validation {
    condition = (
      var.bronze_prefix == trim(var.bronze_prefix, "/") &&
      length(var.bronze_prefix) > 0
    )
    error_message = "bronze_prefix must be non-empty and must not start or end with a slash."
  }
}

variable "noncurrent_version_retention_days" {
  description = "Days to retain superseded object versions for recovery. Current objects never expire."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_version_retention_days >= 30
    error_message = "noncurrent_version_retention_days must be at least 30."
  }
}

variable "tags" {
  description = "Additional tags applied to Bronze storage resources."
  type        = map(string)
  default     = {}
}
