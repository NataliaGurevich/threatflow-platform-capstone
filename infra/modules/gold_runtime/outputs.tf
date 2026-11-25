output "job_name" {
  value = aws_glue_job.this.name
}

output "job_arn" {
  value = aws_glue_job.this.arn
}

output "execution_role_arn" {
  value = aws_iam_role.glue.arn
}

output "catalog_database_name" {
  value = aws_glue_catalog_database.gold.name
}

output "catalog_table_names" {
  value = [
    aws_glue_catalog_table.detail.name,
    aws_glue_catalog_table.summary.name,
  ]
}

output "schedule_name" {
  value = aws_scheduler_schedule.this.name
}

output "schedule_state" {
  value = aws_scheduler_schedule.this.state
}

output "scheduler_dlq_arn" {
  value = aws_sqs_queue.scheduler_dlq.arn
}

output "failure_log_group_name" {
  value = aws_cloudwatch_log_group.glue_failures.name
}

output "failure_alarm_name" {
  value = aws_cloudwatch_metric_alarm.glue_failures.alarm_name
}

output "scheduler_dlq_alarm_name" {
  value = aws_cloudwatch_metric_alarm.scheduler_dlq.alarm_name
}

output "alarm_topic_arn" {
  value = aws_sns_topic.alarms.arn
}
