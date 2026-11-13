variable "name_prefix" {
  type = string
}
variable "image_uri" {
  type = string
}
variable "aws_region" {
  type = string
}
variable "account_id" {
  type = string
}
variable "bronze_bucket_name" {
  type = string
}
variable "bronze_bucket_arn" {
  type = string
}
variable "bronze_prefix" {
  type = string
}
variable "silver_bucket_name" {
  type = string
}
variable "silver_bucket_arn" {
  type = string
}
variable "silver_prefix" {
  type = string
}
variable "visibility_timeout_seconds" {
  type    = number
  default = 1800
}
variable "message_retention_seconds" {
  type    = number
  default = 345600
}
variable "dlq_retention_seconds" {
  type    = number
  default = 1209600
}
variable "max_receive_count" {
  type    = number
  default = 5
}
variable "timeout_seconds" {
  type    = number
  default = 300
}
variable "memory_size_mb" {
  type    = number
  default = 2048
}
variable "maximum_concurrency" {
  type    = number
  default = 2
}
variable "mapping_enabled" {
  type    = bool
  default = false
}
variable "log_retention_days" {
  type    = number
  default = 14
}
variable "minimum_record_count" {
  type    = number
  default = 100
}
variable "minimum_previous_ratio" {
  type    = number
  default = 0.8
}
variable "tags" {
  type    = map(string)
  default = {}
}
