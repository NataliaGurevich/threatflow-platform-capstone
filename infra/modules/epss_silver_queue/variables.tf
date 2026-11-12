variable "queue_name" {
  description = "Name of the Standard queue receiving EPSS Bronze object events."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,80}$", var.queue_name))
    error_message = "queue_name must contain 1-80 alphanumeric, hyphen, or underscore characters."
  }
}

variable "dlq_name" {
  description = "Name of the dead-letter queue for failed EPSS Silver transformations."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,80}$", var.dlq_name))
    error_message = "dlq_name must contain 1-80 alphanumeric, hyphen, or underscore characters."
  }
}

variable "bronze_bucket_arn" {
  description = "ARN of the S3 Bronze bucket allowed to send object notifications."
  type        = string

  validation {
    condition     = can(regex("^arn:[^:]+:s3:::[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.bronze_bucket_arn))
    error_message = "bronze_bucket_arn must be an S3 bucket ARN without an object suffix."
  }
}

variable "source_account_id" {
  description = "AWS account that owns the Bronze bucket; used to prevent a confused deputy."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.source_account_id))
    error_message = "source_account_id must be a 12-digit AWS account ID."
  }
}

variable "visibility_timeout_seconds" {
  description = "Message visibility timeout. Keep at least six times the future Lambda timeout."
  type        = number
  default     = 1800

  validation {
    condition = (
      var.visibility_timeout_seconds >= 60 &&
      var.visibility_timeout_seconds <= 43200 &&
      floor(var.visibility_timeout_seconds) == var.visibility_timeout_seconds
    )
    error_message = "visibility_timeout_seconds must be an integer from 60 through 43200."
  }
}

variable "message_retention_seconds" {
  description = "Seconds that unprocessed messages remain in the source queue."
  type        = number
  default     = 345600

  validation {
    condition = (
      var.message_retention_seconds >= 60 &&
      var.message_retention_seconds <= 1209600 &&
      floor(var.message_retention_seconds) == var.message_retention_seconds
    )
    error_message = "message_retention_seconds must be an integer from 60 through 1209600."
  }
}

variable "dlq_message_retention_seconds" {
  description = "Seconds that failed messages remain in the DLQ; must exceed source retention."
  type        = number
  default     = 1209600

  validation {
    condition = (
      var.dlq_message_retention_seconds >= 60 &&
      var.dlq_message_retention_seconds <= 1209600 &&
      floor(var.dlq_message_retention_seconds) == var.dlq_message_retention_seconds
    )
    error_message = "dlq_message_retention_seconds must be an integer from 60 through 1209600."
  }
}

variable "max_receive_count" {
  description = "Failed receives allowed before SQS moves a message to the DLQ."
  type        = number
  default     = 5

  validation {
    condition = (
      var.max_receive_count >= 1 &&
      var.max_receive_count <= 1000 &&
      floor(var.max_receive_count) == var.max_receive_count
    )
    error_message = "max_receive_count must be an integer from 1 through 1000."
  }
}

variable "tags" {
  description = "Additional tags applied to both queues."
  type        = map(string)
  default     = {}
}
