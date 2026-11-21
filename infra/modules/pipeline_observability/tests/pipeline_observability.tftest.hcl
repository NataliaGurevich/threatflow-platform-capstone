mock_provider "aws" {
  mock_resource "aws_cloudwatch_metric_alarm" {
    defaults = {
      arn = "arn:aws:cloudwatch:eu-central-1:123456789012:alarm:mock"
    }
  }
}

variables {
  name_prefix         = "threatflow-test"
  aws_region          = "eu-central-1"
  cisa_log_group_name = "/aws/lambda/threatflow-cisa-silver-test"
  epss_log_group_name = "/aws/lambda/threatflow-epss-silver-test"
  cisa_function_name  = "threatflow-cisa-silver-test"
  epss_function_name  = "threatflow-epss-silver-test"
  cisa_queue_name     = "threatflow-cisa-events-test"
  epss_queue_name     = "threatflow-epss-events-test"
  cisa_dlq_name       = "threatflow-cisa-events-dlq-test"
  epss_dlq_name       = "threatflow-epss-events-dlq-test"
  nvd_log_group_name  = "/aws/lambda/threatflow-nvd-silver-test"
  nvd_function_name   = "threatflow-nvd-silver-test"
  nvd_queue_name      = "threatflow-nvd-events-test"
  nvd_dlq_name        = "threatflow-nvd-events-dlq-test"
}

run "creates_bounded_pipeline_observability" {
  command = apply

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.audit) == 12
    error_message = "NVD, CISA, and EPSS must each emit received, committed, reused, and failed metrics."
  }

  assert {
    condition = (
      aws_cloudwatch_log_metric_filter.audit["cisa_bronze_received"].log_group_name == var.cisa_log_group_name &&
      one(aws_cloudwatch_log_metric_filter.audit["cisa_bronze_received"].metric_transformation).name == "CISABronzeReceived" &&
      one(aws_cloudwatch_log_metric_filter.audit["cisa_silver_reused"].metric_transformation).name == "CISASilverReused" &&
      aws_cloudwatch_log_metric_filter.audit["epss_processing_failed"].log_group_name == var.epss_log_group_name &&
      one(aws_cloudwatch_log_metric_filter.audit["epss_processing_failed"].metric_transformation).name == "EPSSProcessingFailed"
      && aws_cloudwatch_log_metric_filter.audit["nvd_bronze_received"].log_group_name == var.nvd_log_group_name
      && one(aws_cloudwatch_log_metric_filter.audit["nvd_silver_committed"].metric_transformation).name == "NVDSilverCommitted"
    )
    error_message = "Metric filters must bind each audit event to its source Lambda log group."
  }

  assert {
    condition = alltrue([
      for alarm in aws_cloudwatch_metric_alarm.processing_failed :
      alarm.treat_missing_data == "notBreaching" && alarm.datapoints_to_alarm == 1
    ])
    error_message = "Sparse processing-failure alarms must not alarm when data is missing."
  }

  assert {
    condition = alltrue([
      for alarm in aws_cloudwatch_metric_alarm.queue_age :
      alarm.evaluation_periods == 3 && alarm.datapoints_to_alarm == 2 && alarm.treat_missing_data == "notBreaching"
    ])
    error_message = "Queue-stall alarms must use 2-of-3 evaluation and explicit missing-data behavior."
  }

  assert {
    condition = (
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, "Bronze to Silver health") &&
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, var.cisa_log_group_name) &&
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, var.epss_log_group_name) &&
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, var.nvd_log_group_name) &&
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, "pipeline_event") &&
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, "data volume in selected range") &&
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, "bronze_size_bytes") &&
      strcontains(aws_cloudwatch_dashboard.pipeline.dashboard_body, "record_count")
    )
    error_message = "The dashboard must combine alarms, source metrics, data volume, and recent structured transitions."
  }

  assert {
    condition = alltrue([
      for widget in jsondecode(aws_cloudwatch_dashboard.pipeline.dashboard_body).widgets :
      widget.x >= 0 && widget.x <= 23 && widget.x + widget.width <= 24
    ])
    error_message = "Every dashboard widget must fit inside CloudWatch's 24-column grid."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_dashboard.pipeline.dashboard_body).start == "-P7D" &&
      length([
        for widget in jsondecode(aws_cloudwatch_dashboard.pipeline.dashboard_body).widgets : widget
        if widget.type == "metric" && widget.properties.view == "singleValue" && widget.properties.setPeriodToTimeRange
      ]) == 3 &&
      length([
        for widget in jsondecode(aws_cloudwatch_dashboard.pipeline.dashboard_body).widgets : widget
        if widget.type == "metric" && widget.properties.view == "timeSeries"
      ]) == 3 &&
      length([
        for widget in jsondecode(aws_cloudwatch_dashboard.pipeline.dashboard_body).widgets : widget
        if widget.type == "log" && strcontains(widget.properties.title, "data volume")
      ]) == 3
    )
    error_message = "The dashboard must show weekly pipeline totals, flow, backlog, and per-source data volume."
  }
}
