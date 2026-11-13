output "bronze_bucket_name" {
  description = "Name of the development Bronze S3 bucket."
  value       = module.bronze_storage.bucket_name
}

output "bronze_bucket_arn" {
  description = "ARN of the development Bronze S3 bucket."
  value       = module.bronze_storage.bucket_arn
}

output "bronze_uri" {
  description = "Base S3 URI for development Bronze artifacts."
  value       = module.bronze_storage.bronze_uri
}

output "bronze_access_policy_arn" {
  description = "IAM policy to attach to the future ingestion runtime role."
  value       = module.bronze_storage.access_policy_arn
}

output "silver_bucket_name" {
  description = "Name of the development Silver S3 bucket."
  value       = module.silver_storage.bucket_name
}

output "silver_bucket_arn" {
  description = "ARN of the development Silver S3 bucket."
  value       = module.silver_storage.bucket_arn
}

output "silver_uri" {
  description = "Base S3 URI for development Silver datasets."
  value       = module.silver_storage.silver_uri
}

output "epss_silver_queue_arn" {
  description = "ARN of the EPSS Bronze event queue."
  value       = module.epss_silver_queue.queue_arn
}

output "epss_silver_queue_url" {
  description = "URL of the EPSS Bronze event queue."
  value       = module.epss_silver_queue.queue_url
}

output "epss_bronze_notification_bucket" {
  description = "Bronze bucket publishing filtered EPSS events to SQS."
  value       = module.epss_bronze_notification.bucket_name
}

output "epss_silver_dlq_arn" {
  description = "ARN of the EPSS Silver dead-letter queue."
  value       = module.epss_silver_queue.dlq_arn
}

output "epss_silver_dlq_url" {
  description = "URL of the EPSS Silver dead-letter queue."
  value       = module.epss_silver_queue.dlq_url
}

output "epss_silver_image_repository_arn" {
  description = "ARN of the EPSS Silver Lambda image repository."
  value       = module.epss_silver_image.repository_arn
}

output "epss_silver_image_repository_url" {
  description = "URL used to tag and push the EPSS Silver Lambda image."
  value       = module.epss_silver_image.repository_url
}

output "epss_silver_lambda_function_name" {
  description = "Name of the EPSS Bronze-to-Silver Lambda function."
  value       = module.epss_silver_lambda.function_name
}

output "epss_silver_lambda_function_arn" {
  description = "ARN of the EPSS Bronze-to-Silver Lambda function."
  value       = module.epss_silver_lambda.function_arn
}

output "epss_silver_lambda_execution_role_arn" {
  description = "ARN of the dedicated EPSS Silver Lambda execution role."
  value       = module.epss_silver_lambda.execution_role_arn
}

output "epss_silver_lambda_log_group_name" {
  description = "CloudWatch log group for EPSS Silver Lambda invocations."
  value       = module.epss_silver_lambda.log_group_name
}

output "epss_silver_event_source_mapping_uuid" {
  description = "UUID of the EPSS SQS-to-Lambda event source mapping."
  value       = module.epss_silver_lambda.event_source_mapping_uuid
}

output "cisa_silver_queue_url" {
  value = module.cisa_silver_runtime.queue_url
}

output "cisa_silver_dlq_url" {
  value = module.cisa_silver_runtime.dlq_url
}

output "cisa_silver_image_repository_url" {
  value = module.cisa_silver_runtime.repository_url
}

output "cisa_silver_lambda_function_name" {
  value = module.cisa_silver_runtime.function_name
}

output "airflow_local_user_arn" {
  description = "Local Airflow IAM user ARN, or null when the identity is disabled."
  value       = try(aws_iam_user.airflow_local[0].arn, null)
}
