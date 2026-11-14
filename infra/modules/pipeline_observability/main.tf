locals {
  namespace = "ThreatFlow/Pipeline"
  sources = {
    cisa = {
      label         = "CISA"
      log_group     = var.cisa_log_group_name
      function_name = var.cisa_function_name
      queue_name    = var.cisa_queue_name
      dlq_name      = var.cisa_dlq_name
    }
    epss = {
      label         = "EPSS"
      log_group     = var.epss_log_group_name
      function_name = var.epss_function_name
      queue_name    = var.epss_queue_name
      dlq_name      = var.epss_dlq_name
    }
  }
  audit_events = {
    bronze_received   = "BronzeReceived"
    silver_committed  = "SilverCommitted"
    silver_reused     = "SilverReused"
    processing_failed = "ProcessingFailed"
  }
}

resource "aws_cloudwatch_log_metric_filter" "audit" {
  for_each = {
    for pair in setproduct(keys(local.sources), keys(local.audit_events)) :
    "${pair[0]}_${pair[1]}" => {
      source_key = pair[0]
      event      = pair[1]
    }
  }

  name           = "${var.name_prefix}-${each.key}"
  log_group_name = local.sources[each.value.source_key].log_group
  pattern        = "{ $.message = \"*\\\"event\\\":\\\"${each.value.event}\\\"*\" }"

  metric_transformation {
    name          = "${local.sources[each.value.source_key].label}${local.audit_events[each.value.event]}"
    namespace     = local.namespace
    value         = "1"
    default_value = 0
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "processing_failed" {
  for_each = local.sources

  alarm_name          = "${var.name_prefix}-${each.key}-processing-failed"
  alarm_description   = "${each.value.label} Bronze-to-Silver processing emitted a failure event."
  namespace           = local.namespace
  metric_name         = "${each.value.label}ProcessingFailed"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  tags                = var.tags

  depends_on = [aws_cloudwatch_log_metric_filter.audit]
}

resource "aws_cloudwatch_metric_alarm" "queue_age" {
  for_each = local.sources

  alarm_name          = "${var.name_prefix}-${each.key}-queue-stalled"
  alarm_description   = "${each.value.label} queue has had an old unprocessed message for at least two of three minutes."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = var.queue_age_threshold_seconds
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  dimensions = {
    QueueName = each.value.queue_name
  }
  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  for_each = local.sources

  alarm_name          = "${var.name_prefix}-${each.key}-dlq-not-empty"
  alarm_description   = "${each.value.label} has one or more messages awaiting investigation in its DLQ."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  dimensions = {
    QueueName = each.value.dlq_name
  }
  tags = var.tags
}

resource "aws_cloudwatch_dashboard" "pipeline" {
  dashboard_name = "${var.name_prefix}-bronze-to-silver"
  dashboard_body = jsonencode({
    widgets = concat(
      [{
        type   = "alarm"
        x      = 0
        y      = 0
        width  = 24
        height = 4
        properties = {
          title = "Bronze to Silver health"
          alarms = concat(
            [for alarm in aws_cloudwatch_metric_alarm.processing_failed : alarm.arn],
            [for alarm in aws_cloudwatch_metric_alarm.queue_age : alarm.arn],
            [for alarm in aws_cloudwatch_metric_alarm.dlq_not_empty : alarm.arn]
          )
        }
      }],
      [for index, source_key in sort(keys(local.sources)) : {
        type   = "metric"
        x      = index * 12
        y      = 4
        width  = 12
        height = 6
        properties = {
          title  = "${local.sources[source_key].label}: flow and backlog"
          region = var.aws_region
          period = 300
          stat   = "Sum"
          view   = "timeSeries"
          metrics = [
            [local.namespace, "${local.sources[source_key].label}BronzeReceived", { label = "Bronze received" }],
            [local.namespace, "${local.sources[source_key].label}SilverCommitted", { label = "Silver committed" }],
            [local.namespace, "${local.sources[source_key].label}SilverReused", { label = "Silver reused" }],
            [local.namespace, "${local.sources[source_key].label}ProcessingFailed", { label = "Failed" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", local.sources[source_key].queue_name, { label = "Queue visible", stat = "Maximum" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", local.sources[source_key].dlq_name, { label = "DLQ visible", stat = "Maximum" }],
            ["AWS/Lambda", "Errors", "FunctionName", local.sources[source_key].function_name, { label = "Lambda errors" }]
          ]
        }
      }],
      [for index, source_key in sort(keys(local.sources)) : {
        type   = "log"
        x      = index * 12
        y      = 10
        width  = 12
        height = 8
        properties = {
          title  = "${local.sources[source_key].label}: latest object transitions"
          region = var.aws_region
          view   = "table"
          query  = "SOURCE '${local.sources[source_key].log_group}' | fields @timestamp, @message | filter @message like /pipeline_event/ | sort @timestamp desc | limit 50"
        }
      }]
    )
  })
}
