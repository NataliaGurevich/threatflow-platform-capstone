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
