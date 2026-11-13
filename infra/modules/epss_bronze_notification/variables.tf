variable "bronze_bucket_name" {
  description = "Name of the S3 Bronze bucket publishing EPSS object-created notifications."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bronze_bucket_name))
    error_message = "bronze_bucket_name must be a valid S3 General Purpose bucket name."
  }
}

variable "bronze_prefix" {
  description = "Top-level Bronze key prefix without leading or trailing slashes."
  type        = string
  default     = "bronze"

  validation {
    condition     = can(regex("^[A-Za-z0-9!_.*'()-]+(?:/[A-Za-z0-9!_.*'()-]+)*$", var.bronze_prefix))
    error_message = "bronze_prefix must be a non-empty S3 prefix without leading or trailing slashes."
  }
}

variable "queue_arn" {
  description = "ARN of the Standard SQS queue receiving EPSS Bronze events."
  type        = string

  validation {
    condition     = can(regex("^arn:[^:]+:sqs:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,80}$", var.queue_arn))
    error_message = "queue_arn must be a valid Standard SQS queue ARN."
  }
}

variable "cisa_queue_arn" {
  description = "ARN of the Standard SQS queue receiving CISA Bronze events."
  type        = string
  default     = null
  nullable    = true
}
