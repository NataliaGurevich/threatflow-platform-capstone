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

output "airflow_local_user_arn" {
  description = "Local Airflow IAM user ARN, or null when the identity is disabled."
  value       = try(aws_iam_user.airflow_local[0].arn, null)
}
