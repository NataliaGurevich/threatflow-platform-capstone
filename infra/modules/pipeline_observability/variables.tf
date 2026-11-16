variable "name_prefix" {
  type        = string
  description = "Prefix for dashboard, metric, and alarm names."
}

variable "aws_region" {
  type        = string
  description = "AWS region shown by dashboard widgets."
}

variable "cisa_log_group_name" { type = string }
variable "epss_log_group_name" { type = string }
variable "cisa_function_name" { type = string }
variable "epss_function_name" { type = string }
variable "cisa_queue_name" { type = string }
variable "epss_queue_name" { type = string }
variable "cisa_dlq_name" { type = string }
variable "epss_dlq_name" { type = string }
variable "nvd_log_group_name" { type = string }
variable "nvd_function_name" { type = string }
variable "nvd_queue_name" { type = string }
variable "nvd_dlq_name" { type = string }

variable "queue_age_threshold_seconds" {
  type        = number
  description = "Oldest-message age that indicates a stalled Bronze-to-Silver queue."
  default     = 900
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to supported CloudWatch resources."
  default     = {}
}
