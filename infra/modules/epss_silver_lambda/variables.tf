variable "function_name" {
  description = "Name of the EPSS Bronze-to-Silver Lambda function."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,64}$", var.function_name))
    error_message = "function_name must contain 1-64 alphanumeric, hyphen, or underscore characters."
  }
}

variable "execution_role_name" {
  description = "Name of the dedicated Lambda execution role."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.execution_role_name))
    error_message = "execution_role_name must be a valid IAM role name."
  }
}

variable "image_uri" {
  description = "Immutable private ECR image URI addressed by sha256 digest."
  type        = string

  validation {
    condition = can(regex(
      "^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}$",
      var.image_uri,
    ))
    error_message = "image_uri must be a private ECR URI ending in @sha256:<64 lowercase hex characters>."
  }
}

variable "ecr_repository_name" {
  description = "Name of the ECR repository containing the Lambda image."
  type        = string
}

variable "ecr_repository_url" {
  description = "URL of the ECR repository containing the Lambda image."
  type        = string
}

variable "aws_region" {
  description = "AWS region for the function and S3 clients."
  type        = string
}

variable "bronze_bucket_name" {
  description = "Name of the S3 Bronze bucket."
  type        = string
}

variable "bronze_bucket_arn" {
  description = "ARN of the S3 Bronze bucket."
  type        = string
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

variable "silver_bucket_name" {
  description = "Name of the S3 Silver bucket."
  type        = string
}

variable "silver_bucket_arn" {
  description = "ARN of the S3 Silver bucket."
  type        = string
}

variable "silver_prefix" {
  description = "Top-level Silver key prefix without leading or trailing slashes."
  type        = string
  default     = "silver"

  validation {
    condition     = can(regex("^[A-Za-z0-9!_.*'()-]+(?:/[A-Za-z0-9!_.*'()-]+)*$", var.silver_prefix))
    error_message = "silver_prefix must be a non-empty S3 prefix without leading or trailing slashes."
  }
}

variable "memory_size_mb" {
  description = "Memory allocated to the PyArrow transformation Lambda."
  type        = number
  default     = 2048

  validation {
    condition = (
      var.memory_size_mb >= 128 &&
      var.memory_size_mb <= 10240 &&
      floor(var.memory_size_mb) == var.memory_size_mb
    )
    error_message = "memory_size_mb must be an integer from 128 through 10240."
  }
}

variable "timeout_seconds" {
  description = "Maximum Lambda execution time in seconds."
  type        = number
  default     = 300

  validation {
    condition = (
      var.timeout_seconds >= 1 &&
      var.timeout_seconds <= 900 &&
      floor(var.timeout_seconds) == var.timeout_seconds
    )
    error_message = "timeout_seconds must be an integer from 1 through 900."
  }
}

variable "sqs_queue_arn" {
  description = "ARN of the Standard SQS queue consumed by the Lambda function."
  type        = string

  validation {
    condition     = can(regex("^arn:[^:]+:sqs:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,80}$", var.sqs_queue_arn))
    error_message = "sqs_queue_arn must be a valid Standard SQS queue ARN."
  }
}

variable "sqs_visibility_timeout_seconds" {
  description = "Visibility timeout of the SQS event queue."
  type        = number
}

variable "event_source_mapping_enabled" {
  description = "Whether Lambda actively polls the EPSS event queue."
  type        = bool
  default     = true
}

variable "event_source_maximum_concurrency" {
  description = "Maximum concurrent Lambda invocations started by this SQS mapping."
  type        = number
  default     = 2

  validation {
    condition = (
      var.event_source_maximum_concurrency >= 2 &&
      var.event_source_maximum_concurrency <= 1000 &&
      floor(var.event_source_maximum_concurrency) == var.event_source_maximum_concurrency
    )
    error_message = "event_source_maximum_concurrency must be an integer from 2 through 1000."
  }
}

variable "reserved_concurrent_executions" {
  description = "Reserved Lambda concurrency; -1 uses the shared unreserved account pool."
  type        = number
  default     = -1

  validation {
    condition = (
      var.reserved_concurrent_executions >= -1 &&
      floor(var.reserved_concurrent_executions) == var.reserved_concurrent_executions
    )
    error_message = "reserved_concurrent_executions must be -1 or a non-negative integer."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 14

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.log_retention_days,
    )
    error_message = "log_retention_days must be a retention value supported by CloudWatch Logs."
  }
}

variable "tags" {
  description = "Additional tags applied to the Lambda resources."
  type        = map(string)
  default     = {}
}
