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
    nvd = {
      label         = "NVD"
      log_group     = var.nvd_log_group_name
      function_name = var.nvd_function_name
      queue_name    = var.nvd_queue_name
      dlq_name      = var.nvd_dlq_name
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

resource "aws_sns_topic" "alarms" {
  name = "${var.name_prefix}-bronze-to-silver-alarms"
  tags = var.tags
}

resource "aws_sns_topic_policy" "alarms" {
  arn = aws_sns_topic.alarms.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarmPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alarms.arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:cloudwatch:${var.aws_region}:${var.account_id}:alarm:${var.name_prefix}-*" }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count = var.notification_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.notification_email
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
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
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
  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
  tags          = var.tags
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
  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
  tags          = var.tags
}

resource "aws_cloudwatch_dashboard" "pipeline" {
  dashboard_name = "${var.name_prefix}-bronze-to-silver"
  dashboard_body = jsonencode({
    start          = "-P7D"
    periodOverride = "inherit"
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
        x      = index * 8
        y      = 4
        width  = 8
        height = 3
        properties = {
          title                = "${local.sources[source_key].label}: events in selected range"
          region               = var.aws_region
          period               = 300
          stat                 = "Sum"
          view                 = "singleValue"
          setPeriodToTimeRange = true
          sparkline            = false
          metrics = [
            [local.namespace, "${local.sources[source_key].label}BronzeReceived", { label = "Bronze received" }],
            [local.namespace, "${local.sources[source_key].label}SilverCommitted", { label = "Silver committed" }],
            [local.namespace, "${local.sources[source_key].label}SilverReused", { label = "Silver reused" }],
            [local.namespace, "${local.sources[source_key].label}ProcessingFailed", { label = "Failed" }]
          ]
        }
      }],
      [for index, source_key in sort(keys(local.sources)) : {
        type   = "metric"
        x      = index * 8
        y      = 7
        width  = 8
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
        x      = index * 8
        y      = 13
        width  = 8
        height = 5
        properties = {
          title  = "${local.sources[source_key].label}: data volume in selected range"
          region = var.aws_region
          view   = "table"
          query  = "SOURCE '${local.sources[source_key].log_group}' | fields jsonParse(message) as pipeline | filter pipeline.event_type = \"pipeline_event\" | filter pipeline.event in [\"bronze_received\", \"silver_committed\", \"silver_reused\"] | stats count(*) as events, sum(pipeline.bronze_size_bytes) / 1024 / 1024 as bronze_mib, sum(pipeline.record_count) as records by pipeline.event"
        }
      }],
      [for index, source_key in sort(keys(local.sources)) : {
        type   = "log"
        x      = index * 8
        y      = 18
        width  = 8
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
