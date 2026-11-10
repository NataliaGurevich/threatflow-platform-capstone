output "bucket_name" {
  description = "Name of the Bronze S3 bucket."
  value       = aws_s3_bucket.bronze.id
}

output "bucket_arn" {
  description = "ARN of the Bronze S3 bucket."
  value       = aws_s3_bucket.bronze.arn
}

output "bronze_prefix" {
  description = "Key prefix reserved for Bronze artifacts."
  value       = var.bronze_prefix
}

output "bronze_uri" {
  description = "Base S3 URI for Bronze artifacts."
  value       = "s3://${aws_s3_bucket.bronze.id}/${var.bronze_prefix}"
}

output "access_policy_arn" {
  description = "IAM policy ARN to attach to the future ingestion runtime role."
  value       = aws_iam_policy.bronze_access.arn
}
