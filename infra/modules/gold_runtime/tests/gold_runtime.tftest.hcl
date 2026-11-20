mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock"
      id  = "mock"
    }
  }

  mock_resource "aws_glue_job" {
    defaults = {
      arn = "arn:aws:glue:eu-central-1:123456789012:job/threatflow-vulnerability-priority-gold-test"
    }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws:sqs:eu-central-1:123456789012:threatflow-vulnerability-priority-gold-test-scheduler-dlq"
      id  = "https://sqs.eu-central-1.amazonaws.com/123456789012/mock"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:eu-central-1:123456789012:log-group:/aws/events/threatflow-vulnerability-priority-gold-test-failures"
    }
  }

  mock_resource "aws_cloudwatch_event_rule" {
    defaults = {
      arn = "arn:aws:events:eu-central-1:123456789012:rule/threatflow-vulnerability-priority-gold-test-failures"
    }
  }
}

variables {
  name_prefix        = "threatflow-vulnerability-priority-gold-test"
  aws_region         = "eu-central-1"
  account_id         = "123456789012"
  silver_bucket_name = "threatflow-silver-test"
  silver_bucket_arn  = "arn:aws:s3:::threatflow-silver-test"
  gold_bucket_name   = "threatflow-gold-test"
  script_s3_uri      = "s3://threatflow-silver-test/_artifacts/glue/releases/release-1/vulnerability_priority_job.py"
  wheel_s3_uri       = "s3://threatflow-silver-test/_artifacts/glue/releases/release-1/threatflow-0.1.0-py3-none-any.whl"
}

run "creates_disabled_daily_auto_gold_runtime" {
  command = apply

  assert {
    condition = (
      aws_glue_job.this.name == var.name_prefix &&
      aws_glue_job.this.glue_version == "6.0" &&
      aws_glue_job.this.worker_type == "G.1X" &&
      aws_glue_job.this.number_of_workers == 2 &&
      aws_glue_job.this.default_arguments["--snapshot_date"] == "AUTO" &&
      aws_glue_job.this.default_arguments["--max_input_lag_days"] == "2" &&
      aws_glue_job.this.default_arguments["--catalog_database"] == "threatflow_gold" &&
      aws_glue_job.this.default_arguments["--gold_bucket"] == var.gold_bucket_name
    )
    error_message = "The daily Glue job must use AUTO inputs and the dedicated Gold bucket."
  }


  assert {
    condition = (
      aws_glue_catalog_database.gold.name == "threatflow_gold" &&
      aws_glue_catalog_table.detail.name == "vulnerability_priority_daily" &&
      aws_glue_catalog_table.summary.name == "vulnerability_priority_summary_daily" &&
      one(aws_glue_catalog_table.detail.partition_keys).name == "snapshot_date" &&
      one(aws_glue_catalog_table.detail.partition_keys).type == "date" &&
      length(one(aws_glue_catalog_table.detail.storage_descriptor).columns) == 26 &&
      length(one(aws_glue_catalog_table.summary.storage_descriptor).columns) == 12
    )
    error_message = "Gold Catalog must expose both Parquet datasets partitioned by snapshot_date."
  }

  assert {
    condition = (
      aws_scheduler_schedule.this.state == "DISABLED" &&
      aws_scheduler_schedule.this.schedule_expression == "cron(0 9 * * ? *)" &&
      aws_scheduler_schedule.this.schedule_expression_timezone == "Europe/Berlin" &&
      one(aws_scheduler_schedule.this.flexible_time_window).mode == "OFF"
    )
    error_message = "The schedule must default to a disabled exact 09:00 Europe/Berlin run."
  }

  assert {
    condition = (
      jsondecode(one(aws_scheduler_schedule.this.target).input).JobName == var.name_prefix &&
      jsondecode(one(aws_scheduler_schedule.this.target).input).Arguments["--snapshot_date"] == "AUTO" &&
      one(aws_scheduler_schedule.this.target).retry_policy[0].maximum_retry_attempts == 2
    )
    error_message = "Scheduler must invoke the exact Glue job in AUTO mode with bounded retries."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.glue.assume_role_policy).Statement[0].Principal.Service == "glue.amazonaws.com" &&
      jsondecode(aws_iam_role.scheduler.assume_role_policy).Statement[0].Principal.Service == "scheduler.amazonaws.com" &&
      jsondecode(aws_iam_role.scheduler.assume_role_policy).Statement[0].Condition.ArnEquals["aws:SourceArn"] == "arn:aws:scheduler:eu-central-1:123456789012:schedule-group/threatflow-vulnerability-priority-gold-test-schedules" &&
      strcontains(aws_iam_role_policy.glue_s3.policy, "threatflow-silver-test") &&
      strcontains(aws_iam_role_policy.glue_s3.policy, "threatflow-gold-test")
    )
    error_message = "Glue and Scheduler must have separate service roles and scoped S3 policies."
  }


  assert {
    condition = (
      strcontains(aws_iam_role_policy.glue_catalog.policy, "glue:CreatePartition") &&
      strcontains(aws_iam_role_policy.glue_catalog.policy, "table/threatflow_gold/vulnerability_priority_daily") &&
      strcontains(aws_iam_role_policy.glue_catalog.policy, "table/threatflow_gold/vulnerability_priority_summary_daily")
    )
    error_message = "Glue must have narrowly scoped permissions to register Gold partitions."
  }

  assert {
    condition = (
      aws_cloudwatch_event_rule.glue_failures.event_pattern != "" &&
      aws_cloudwatch_metric_alarm.glue_failures.treat_missing_data == "notBreaching"
    )
    error_message = "Terminal Glue failures must be captured and alarmed without false missing-data alarms."
  }
}

run "rejects_observed_with_incomplete_nvd_history" {
  command = plan

  variables {
    snapshot_type        = "OBSERVED"
    nvd_history_complete = false
  }

  expect_failures = [aws_glue_job.this]
}
