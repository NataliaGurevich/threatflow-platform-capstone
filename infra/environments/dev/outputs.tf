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
