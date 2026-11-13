output "function_name" {
  description = "Name of the EPSS Silver Lambda function."
  value       = aws_lambda_function.this.function_name
}

output "function_arn" {
  description = "ARN of the EPSS Silver Lambda function."
  value       = aws_lambda_function.this.arn
}

output "execution_role_arn" {
  description = "ARN of the dedicated Lambda execution role."
  value       = aws_iam_role.this.arn
}

output "log_group_name" {
  description = "CloudWatch log group receiving structured Lambda logs."
  value       = aws_cloudwatch_log_group.this.name
}

output "event_source_mapping_uuid" {
  description = "UUID of the SQS-to-Lambda event source mapping."
  value       = aws_lambda_event_source_mapping.sqs.uuid
}
