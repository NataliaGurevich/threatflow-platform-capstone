output "queue_arn" { value = aws_sqs_queue.events.arn }
output "queue_url" { value = aws_sqs_queue.events.id }
output "dlq_arn" { value = aws_sqs_queue.dlq.arn }
output "dlq_url" { value = aws_sqs_queue.dlq.id }
output "repository_url" { value = aws_ecr_repository.this.repository_url }
output "function_name" { value = aws_lambda_function.this.function_name }
output "function_arn" { value = aws_lambda_function.this.arn }
