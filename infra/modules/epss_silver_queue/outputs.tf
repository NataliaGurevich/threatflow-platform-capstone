output "queue_name" {
  description = "Name of the EPSS Bronze event queue."
  value       = aws_sqs_queue.events.name
}

output "queue_arn" {
  description = "ARN of the EPSS Bronze event queue."
  value       = aws_sqs_queue.events.arn
}

output "queue_url" {
  description = "URL of the EPSS Bronze event queue."
  value       = aws_sqs_queue.events.id
}

output "dlq_name" {
  description = "Name of the EPSS Silver dead-letter queue."
  value       = aws_sqs_queue.dlq.name
}

output "dlq_arn" {
  description = "ARN of the EPSS Silver dead-letter queue."
  value       = aws_sqs_queue.dlq.arn
}

output "dlq_url" {
  description = "URL of the EPSS Silver dead-letter queue."
  value       = aws_sqs_queue.dlq.id
}
