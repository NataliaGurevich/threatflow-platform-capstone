variable "bucket_name" {
  description = "Globally unique name for the ThreatFlow Silver S3 bucket."
  type        = string

  validation {
    condition = (
      length(var.bucket_name) >= 3 &&
      length(var.bucket_name) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.bucket_name)) &&
      !strcontains(var.bucket_name, "..")
    )
    error_message = "bucket_name must satisfy the basic lowercase S3 naming constraints."
  }
}

variable "silver_prefix" {
  description = "Key prefix reserved for committed Silver datasets."
  type        = string
  default     = "silver"

  validation {
    condition = (
      var.silver_prefix == trim(var.silver_prefix, "/") &&
      length(var.silver_prefix) > 0
    )
    error_message = "silver_prefix must be non-empty and must not start or end with a slash."
  }
}

variable "noncurrent_version_retention_days" {
  description = "Days to retain superseded Silver object versions for recovery."
  type        = number
  default     = 30

  validation {
    condition     = var.noncurrent_version_retention_days >= 7
    error_message = "noncurrent_version_retention_days must be at least 7."
  }
}

variable "tags" {
  description = "Additional tags applied to Silver storage resources."
  type        = map(string)
  default     = {}
}
