output "dashboard_name" {
  description = "CloudWatch dashboard containing CISA and EPSS Bronze-to-Silver health."
  value       = aws_cloudwatch_dashboard.pipeline.dashboard_name
}

output "dashboard_arn" {
  description = "ARN of the Bronze-to-Silver CloudWatch dashboard."
  value       = aws_cloudwatch_dashboard.pipeline.dashboard_arn
}

output "alarm_names" {
  description = "CloudWatch alarm names shown on the dashboard."
  value = concat(
    [for alarm in aws_cloudwatch_metric_alarm.processing_failed : alarm.alarm_name],
    [for alarm in aws_cloudwatch_metric_alarm.queue_age : alarm.alarm_name],
    [for alarm in aws_cloudwatch_metric_alarm.dlq_not_empty : alarm.alarm_name],
  )
}

output "alarm_topic_arn" {
  description = "SNS topic receiving Bronze-to-Silver alarm state changes."
  value       = aws_sns_topic.alarms.arn
}
