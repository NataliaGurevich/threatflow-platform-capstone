mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/threatflow-epss-silver-test-execution"
      id  = "threatflow-epss-silver-test-execution"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:eu-central-1:123456789012:log-group:/aws/lambda/threatflow-epss-silver-test"
    }
  }
}

variables {
  function_name                  = "threatflow-epss-silver-test"
  execution_role_name            = "threatflow-epss-silver-test-execution"
  image_uri                      = "123456789012.dkr.ecr.eu-central-1.amazonaws.com/threatflow/epss-silver@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ecr_repository_name            = "threatflow/epss-silver"
  ecr_repository_url             = "123456789012.dkr.ecr.eu-central-1.amazonaws.com/threatflow/epss-silver"
  aws_region                     = "eu-central-1"
  bronze_bucket_name             = "threatflow-bronze-test-123456"
  bronze_bucket_arn              = "arn:aws:s3:::threatflow-bronze-test-123456"
  bronze_prefix                  = "bronze"
  silver_bucket_name             = "threatflow-silver-test-123456"
  silver_bucket_arn              = "arn:aws:s3:::threatflow-silver-test-123456"
  silver_prefix                  = "silver"
  sqs_queue_arn                  = "arn:aws:sqs:eu-central-1:123456789012:threatflow-epss-bronze-events-test"
  sqs_visibility_timeout_seconds = 1800
  tags = {
    Environment = "test"
    Project     = "ThreatFlow"
  }
}

run "creates_least_privilege_arm64_image_lambda" {
  command = apply

  assert {
    condition = (
      aws_lambda_function.this.package_type == "Image" &&
      one(aws_lambda_function.this.architectures) == "arm64" &&
      aws_lambda_function.this.image_uri == var.image_uri &&
      aws_lambda_function.this.memory_size == 2048 &&
      aws_lambda_function.this.timeout == 300 &&
      aws_lambda_function.this.reserved_concurrent_executions == -1
    )
    error_message = "Lambda must use the immutable ARM64 image and shared unreserved concurrency."
  }

  assert {
    condition = (
      one(aws_lambda_function.this.environment).variables["THREATFLOW_S3_BRONZE_BUCKET"] == var.bronze_bucket_name &&
      one(aws_lambda_function.this.environment).variables["THREATFLOW_S3_BRONZE_PREFIX"] == "bronze" &&
      one(aws_lambda_function.this.environment).variables["THREATFLOW_S3_SILVER_BUCKET"] == var.silver_bucket_name &&
      one(aws_lambda_function.this.environment).variables["THREATFLOW_S3_SILVER_PREFIX"] == "silver"
    )
    error_message = "Lambda must receive the exact Bronze and Silver storage configuration."
  }

  assert {
    condition = (
      aws_cloudwatch_log_group.this.name == "/aws/lambda/${var.function_name}" &&
      aws_cloudwatch_log_group.this.retention_in_days == 30 &&
      one(aws_lambda_function.this.logging_config).log_format == "JSON"
    )
    error_message = "The function must use a pre-created JSON log group with bounded retention."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Principal.Service == "lambda.amazonaws.com" &&
      jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Action == "sts:AssumeRole"
    )
    error_message = "Only the Lambda service may assume the execution role."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[0].Action == ["s3:GetObjectVersion"] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[0].Resource == ["${var.bronze_bucket_arn}/bronze/source=epss/*"] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[1].Action == ["s3:GetObject", "s3:PutObject"] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[1].Resource == ["${var.silver_bucket_arn}/silver/epss_scores/*"] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[2].Action == ["s3:ListBucket"] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[2].Resource == [var.silver_bucket_arn] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[2].Condition.StringLike["s3:prefix"] == ["silver/epss_scores/*"]
    )
    error_message = "S3 permissions must be limited to EPSS Bronze versions and the EPSS Silver dataset prefix."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[3].Action == ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[3].Resource == [var.sqs_queue_arn] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[4].Action == ["logs:CreateLogStream", "logs:PutLogEvents"] &&
      jsondecode(aws_iam_role_policy.runtime.policy).Statement[4].Resource == ["${aws_cloudwatch_log_group.this.arn}:*"] &&
      !strcontains(aws_iam_role_policy.runtime.policy, "s3:DeleteObject") &&
      !strcontains(aws_iam_role_policy.runtime.policy, "logs:CreateLogGroup") &&
      !strcontains(aws_iam_role_policy.runtime.policy, "kms:")
    )
    error_message = "The execution role must contain only the exact queue polling and existing scoped permissions."
  }

  assert {
    condition = (
      aws_lambda_event_source_mapping.sqs.event_source_arn == var.sqs_queue_arn &&
      aws_lambda_event_source_mapping.sqs.function_name == var.function_name &&
      aws_lambda_event_source_mapping.sqs.enabled &&
      aws_lambda_event_source_mapping.sqs.batch_size == 1 &&
      aws_lambda_event_source_mapping.sqs.maximum_batching_window_in_seconds == 0 &&
      aws_lambda_event_source_mapping.sqs.function_response_types == toset(["ReportBatchItemFailures"]) &&
      one(aws_lambda_event_source_mapping.sqs.scaling_config).maximum_concurrency == 2
    )
    error_message = "The SQS mapping must use single-message batches, partial failures, and bounded concurrency."
  }

  assert {
    condition = (
      jsondecode(aws_ecr_repository_policy.lambda.policy).Statement[0].Principal.Service == "lambda.amazonaws.com" &&
      jsondecode(aws_ecr_repository_policy.lambda.policy).Statement[0].Action == ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"] &&
      jsondecode(aws_ecr_repository_policy.lambda.policy).Statement[0].Sid == "LambdaECRImageRetrievalPolicy" &&
      !contains(keys(jsondecode(aws_ecr_repository_policy.lambda.policy).Statement[0]), "Resource") &&
      !contains(keys(jsondecode(aws_ecr_repository_policy.lambda.policy).Statement[0]), "Condition")
    )
    error_message = "Same-account ECR image retrieval must match the minimum AWS Lambda repository policy."
  }
}

run "rejects_tag_only_image_uri" {
  command = plan

  variables {
    image_uri = "123456789012.dkr.ecr.eu-central-1.amazonaws.com/threatflow/epss-silver:latest"
  }

  expect_failures = [var.image_uri]
}

run "rejects_incompatible_queue_visibility" {
  command = plan

  variables {
    sqs_visibility_timeout_seconds = 1799
  }

  expect_failures = [aws_lambda_function.this]
}

run "rejects_invalid_event_source_concurrency" {
  command = plan

  variables {
    event_source_maximum_concurrency = 1
  }

  expect_failures = [var.event_source_maximum_concurrency]
}
