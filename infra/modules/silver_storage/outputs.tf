output "bucket_name" {
  description = "Name of the Silver S3 bucket."
  value       = aws_s3_bucket.silver.id
}

output "bucket_arn" {
  description = "ARN of the Silver S3 bucket."
  value       = aws_s3_bucket.silver.arn
}

output "silver_prefix" {
  description = "Key prefix reserved for Silver datasets."
  value       = var.silver_prefix
}

output "silver_uri" {
  description = "Base S3 URI for Silver datasets."
  value       = "s3://${aws_s3_bucket.silver.id}/${var.silver_prefix}"
}
