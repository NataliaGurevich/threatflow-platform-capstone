mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/threatflow-nvd-silver-test-execution"
      id  = "threatflow-nvd-silver-test-execution"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:eu-central-1:123456789012:log-group:/aws/lambda/threatflow-nvd-silver-test"
    }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws:sqs:eu-central-1:123456789012:threatflow-nvd-silver-test-events"
      id  = "https://sqs.eu-central-1.amazonaws.com/123456789012/threatflow-nvd-silver-test-events"
      url = "https://sqs.eu-central-1.amazonaws.com/123456789012/threatflow-nvd-silver-test-events"
    }
  }

  mock_resource "aws_ecr_repository" {
    defaults = {
      repository_url = "123456789012.dkr.ecr.eu-central-1.amazonaws.com/threatflow-nvd-silver-test"
    }
  }
}

variables {
  name_prefix        = "threatflow-nvd-silver-test"
  image_uri          = "123456789012.dkr.ecr.eu-central-1.amazonaws.com/threatflow-nvd-silver-test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  aws_region         = "eu-central-1"
  account_id         = "123456789012"
  bronze_bucket_name = "threatflow-bronze-test"
  bronze_bucket_arn  = "arn:aws:s3:::threatflow-bronze-test"
  bronze_prefix      = "bronze"
  silver_bucket_name = "threatflow-silver-test"
  silver_bucket_arn  = "arn:aws:s3:::threatflow-silver-test"
  silver_prefix      = "silver"
}

run "creates_bounded_nvd_runtime" {
  command = apply

  assert {
    condition = (
      aws_lambda_event_source_mapping.this.batch_size == 1 &&
      contains(aws_lambda_event_source_mapping.this.function_response_types, "ReportBatchItemFailures") &&
      one(aws_lambda_event_source_mapping.this.scaling_config).maximum_concurrency == 2
    )
    error_message = "NVD SQS mapping must use bounded concurrency and partial failures."
  }

  assert {
    condition = (
      aws_sqs_queue.events.receive_wait_time_seconds == 20 &&
      aws_sqs_queue.events.visibility_timeout_seconds >= 6 * aws_lambda_function.this.timeout
    )
    error_message = "NVD queue must use long polling and a safe Lambda visibility timeout."
  }

  assert {
    condition = (
      strcontains(aws_iam_role_policy.runtime.policy, "bronze/source=nvd/*") &&
      strcontains(aws_iam_role_policy.runtime.policy, "silver/nvd_cve_windows/*") &&
      !strcontains(aws_iam_role_policy.runtime.policy, "s3:DeleteObject") &&
      !strcontains(aws_iam_role_policy.runtime.policy, "s3:PutObjectAcl")
    )
    error_message = "NVD runtime IAM must remain prefix-scoped and exclude destructive or ACL actions."
  }
}
