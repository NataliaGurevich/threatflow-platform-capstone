output "bucket_name" {
  description = "Bronze bucket with the EPSS object-created notification configured."
  value       = aws_s3_bucket_notification.this.bucket
}
