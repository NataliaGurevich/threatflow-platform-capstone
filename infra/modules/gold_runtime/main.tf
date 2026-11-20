locals {
  gold_bucket_arn      = "arn:aws:s3:::${var.gold_bucket_name}"
  silver_objects       = "${var.silver_bucket_arn}/${var.silver_prefix}/*"
  artifact_objects     = "${var.silver_bucket_arn}/_artifacts/glue/releases/*"
  gold_objects         = "${local.gold_bucket_arn}/${var.gold_prefix}/*"
  scheduler_name       = "${var.name_prefix}-daily"
  scheduler_group_name = "${var.name_prefix}-schedules"
  scheduler_group_arn  = "arn:aws:scheduler:${var.aws_region}:${var.account_id}:schedule-group/${local.scheduler_group_name}"

  detail_columns = [
    { name = "snapshot_type", type = "string" },
    { name = "nvd_history_complete", type = "boolean" },
    { name = "source_cutoff", type = "timestamp" },
    { name = "cve_id", type = "string" },
    { name = "priority_tier", type = "string" },
    { name = "priority_reason", type = "string" },
    { name = "is_kev", type = "boolean" },
    { name = "vendor_project", type = "string" },
    { name = "product", type = "string" },
    { name = "vulnerability_name", type = "string" },
    { name = "known_ransomware_campaign_use", type = "string" },
    { name = "kev_date_added", type = "date" },
    { name = "cisa_due_date", type = "date" },
    { name = "nvd_published", type = "timestamp" },
    { name = "nvd_last_modified", type = "timestamp" },
    { name = "cvss_version", type = "string" },
    { name = "cvss_score", type = "double" },
    { name = "cvss_severity", type = "string" },
    { name = "epss_score_date", type = "date" },
    { name = "epss_score", type = "double" },
    { name = "epss_percentile", type = "double" },
    { name = "epss_7d_ago", type = "double" },
    { name = "epss_7d_change", type = "double" },
    { name = "generated_at", type = "timestamp" },
    { name = "policy_version", type = "string" },
    { name = "input_fingerprint", type = "string" },
  ]

  summary_columns = [
    { name = "snapshot_type", type = "string" },
    { name = "nvd_history_complete", type = "boolean" },
    { name = "priority_tier", type = "string" },
    { name = "vulnerability_count", type = "bigint" },
    { name = "ransomware_count", type = "bigint" },
    { name = "overdue_kev_count", type = "bigint" },
    { name = "critical_count", type = "bigint" },
    { name = "average_epss", type = "double" },
    { name = "maximum_epss", type = "double" },
    { name = "generated_at", type = "timestamp" },
    { name = "policy_version", type = "string" },
    { name = "input_fingerprint", type = "string" },
  ]
}

resource "aws_iam_role" "glue" {
  name = "${var.name_prefix}-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "glue_service" {
  role       = aws_iam_role.glue.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_s3" {
  name = "${var.name_prefix}-s3"
  role = aws_iam_role.glue.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListSilverInputsAndArtifacts"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = var.silver_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["${var.silver_prefix}/*", "_artifacts/glue/releases/*"]
          }
        }
      },
      {
        Sid      = "LocateSilverBucket"
        Effect   = "Allow"
        Action   = "s3:GetBucketLocation"
        Resource = var.silver_bucket_arn
      },
      {
        Sid      = "ReadSilverInputsAndArtifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = [local.silver_objects, local.artifact_objects]
      },
      {
        Sid      = "LocateGoldBucket"
        Effect   = "Allow"
        Action   = "s3:GetBucketLocation"
        Resource = local.gold_bucket_arn
      },
      {
        Sid      = "ListGoldObjects"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:ListBucketMultipartUploads"]
        Resource = local.gold_bucket_arn
        Condition = {
          StringLike = { "s3:prefix" = "${var.gold_prefix}/*" }
        }
      },
      {
        Sid    = "ManageGoldObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:AbortMultipartUpload",
          "s3:ListMultipartUploadParts",
        ]
        Resource = local.gold_objects
      },
    ]
  })
}

resource "aws_iam_role_policy" "glue_catalog" {
  name = "${var.name_prefix}-catalog"
  role = aws_iam_role.glue.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "RegisterCommittedGoldPartitions"
      Effect = "Allow"
      Action = [
        "glue:GetDatabase",
        "glue:GetTable",
        "glue:GetPartition",
        "glue:GetPartitions",
        "glue:CreatePartition",
      ]
      Resource = [
        "arn:aws:glue:${var.aws_region}:${var.account_id}:catalog",
        "arn:aws:glue:${var.aws_region}:${var.account_id}:database/${var.catalog_database}",
        "arn:aws:glue:${var.aws_region}:${var.account_id}:table/${var.catalog_database}/vulnerability_priority_daily",
        "arn:aws:glue:${var.aws_region}:${var.account_id}:table/${var.catalog_database}/vulnerability_priority_summary_daily",
      ]
    }]
  })
}

resource "aws_glue_catalog_database" "gold" {
  name        = var.catalog_database
  description = "ThreatFlow curated Gold datasets for Athena and Metabase."
}

resource "aws_glue_catalog_table" "detail" {
  name          = "vulnerability_priority_daily"
  database_name = aws_glue_catalog_database.gold.name
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    classification = "parquet"
    EXTERNAL       = "TRUE"
  }

  partition_keys {
    name = "snapshot_date"
    type = "date"
  }

  storage_descriptor {
    location      = "s3://${var.gold_bucket_name}/${var.gold_prefix}/vulnerability_priority_daily/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    dynamic "columns" {
      for_each = local.detail_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
  }
}

resource "aws_glue_catalog_table" "summary" {
  name          = "vulnerability_priority_summary_daily"
  database_name = aws_glue_catalog_database.gold.name
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    classification = "parquet"
    EXTERNAL       = "TRUE"
  }

  partition_keys {
    name = "snapshot_date"
    type = "date"
  }

  storage_descriptor {
    location      = "s3://${var.gold_bucket_name}/${var.gold_prefix}/vulnerability_priority_summary_daily/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    dynamic "columns" {
      for_each = local.summary_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
  }
}

resource "aws_glue_job" "this" {
  name              = var.name_prefix
  role_arn          = aws_iam_role.glue.arn
  glue_version      = "6.0"
  worker_type       = var.worker_type
  number_of_workers = var.number_of_workers
  timeout           = var.timeout_minutes
  max_retries       = 0
  execution_class   = "STANDARD"

  execution_property {
    max_concurrent_runs = 1
  }

  command {
    name            = "glueetl"
    python_version  = "3"
    script_location = var.script_s3_uri
  }

  default_arguments = {
    "--job-language"                     = "python"
    "--silver_bucket"                    = var.silver_bucket_name
    "--silver_prefix"                    = var.silver_prefix
    "--gold_bucket"                      = var.gold_bucket_name
    "--gold_prefix"                      = var.gold_prefix
    "--catalog_database"                 = aws_glue_catalog_database.gold.name
    "--snapshot_date"                    = "AUTO"
    "--snapshot_type"                    = var.snapshot_type
    "--nvd_history_complete"             = tostring(var.nvd_history_complete)
    "--max_input_lag_days"               = tostring(var.max_input_lag_days)
    "--extra-py-files"                   = var.wheel_s3_uri
    "--TempDir"                          = "s3://${var.gold_bucket_name}/${var.gold_prefix}/_temporary/glue/"
    "--spark-event-logs-path"            = "s3://${var.gold_bucket_name}/${var.gold_prefix}/_spark-logs/glue/"
    "--job-bookmark-option"              = "job-bookmark-disable"
    "--enable-glue-datacatalog"          = ""
    "--enable-metrics"                   = ""
    "--enable-spark-ui"                  = "true"
    "--enable-continuous-cloudwatch-log" = "true"
    "--enable-observability-metrics"     = "true"
    "--enable-job-insights"              = "false"
    "--conf"                             = "spark.eventLog.rolling.enabled=true --conf spark.sql.catalog.glue_catalog.glue.skip-name-validation=true"
  }

  tags = var.tags
  depends_on = [
    aws_glue_catalog_table.detail,
    aws_glue_catalog_table.summary,
    aws_iam_role_policy.glue_catalog,
    aws_iam_role_policy.glue_s3,
    aws_iam_role_policy_attachment.glue_service,
  ]

  lifecycle {
    precondition {
      condition     = var.snapshot_type != "OBSERVED" || var.nvd_history_complete
      error_message = "OBSERVED Gold requires nvd_history_complete=true."
    }
    precondition {
      condition     = var.gold_bucket_name != "" && var.script_s3_uri != "" && var.wheel_s3_uri != ""
      error_message = "Gold bucket, script URI, and wheel URI must be configured."
    }
  }
}

resource "aws_sqs_queue" "scheduler_dlq" {
  name                      = "${var.name_prefix}-scheduler-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = var.tags
}

resource "aws_sqs_queue_policy" "scheduler_dlq" {
  queue_url = aws_sqs_queue.scheduler_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.scheduler_dlq.arn
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_scheduler_schedule_group" "this" {
  name = local.scheduler_group_name
  tags = var.tags
}

resource "aws_iam_role" "scheduler" {
  name = "${var.name_prefix}-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnEquals    = { "aws:SourceArn" = local.scheduler_group_arn }
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "scheduler" {
  name = "${var.name_prefix}-scheduler"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "glue:StartJobRun"
        Resource = aws_glue_job.this.arn
      },
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.scheduler_dlq.arn
      },
    ]
  })
}

resource "aws_scheduler_schedule" "this" {
  name                         = local.scheduler_name
  group_name                   = aws_scheduler_schedule_group.this.name
  description                  = "Build the latest ready ThreatFlow vulnerability-priority Gold snapshot."
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = var.schedule_timezone
  state                        = var.schedule_enabled ? "ENABLED" : "DISABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:glue:startJobRun"
    role_arn = aws_iam_role.scheduler.arn
    input = jsonencode({
      JobName = aws_glue_job.this.name
      Arguments = {
        "--snapshot_date"      = "AUTO"
        "--max_input_lag_days" = tostring(var.max_input_lag_days)
      }
    })

    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 2
    }

    dead_letter_config {
      arn = aws_sqs_queue.scheduler_dlq.arn
    }
  }

  depends_on = [aws_iam_role_policy.scheduler, aws_sqs_queue_policy.scheduler_dlq]
}

resource "aws_cloudwatch_log_group" "glue_failures" {
  name              = "/aws/events/${var.name_prefix}-failures"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_event_rule" "glue_failures" {
  name        = "${var.name_prefix}-failures"
  description = "Capture terminal failures from the Terraform-managed Gold Glue job."
  event_pattern = jsonencode({
    source      = ["aws.glue"]
    detail-type = ["Glue Job State Change"]
    detail = {
      jobName = [aws_glue_job.this.name]
      state   = ["FAILED", "TIMEOUT", "STOPPED"]
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "glue_failures" {
  rule = aws_cloudwatch_event_rule.glue_failures.name
  arn  = aws_cloudwatch_log_group.glue_failures.arn
}

resource "aws_cloudwatch_log_resource_policy" "eventbridge" {
  policy_name = "${var.name_prefix}-eventbridge-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.glue_failures.arn}:*"
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.glue_failures.arn }
      }
    }]
  })
}

resource "aws_cloudwatch_log_metric_filter" "glue_failures" {
  name           = "${var.name_prefix}-failures"
  pattern        = ""
  log_group_name = aws_cloudwatch_log_group.glue_failures.name

  metric_transformation {
    name      = "GoldGlueTerminalFailures"
    namespace = "ThreatFlow/Gold"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "glue_failures" {
  alarm_name          = "${var.name_prefix}-terminal-failure"
  alarm_description   = "The daily vulnerability-priority Gold Glue job failed, timed out, or stopped."
  namespace           = "ThreatFlow/Gold"
  metric_name         = "GoldGlueTerminalFailures"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  tags                = var.tags
}
