locals {
  bronze_objects = "${var.bronze_bucket_arn}/${var.bronze_prefix}/source=cisa_kev/*"
  silver_objects = "${var.silver_bucket_arn}/${var.silver_prefix}/cisa_kev_snapshots/*"
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-events-dlq"
  message_retention_seconds = var.dlq_retention_seconds
  sqs_managed_sse_enabled   = true
  tags                      = var.tags
}

resource "aws_sqs_queue" "events" {
  name                       = "${var.name_prefix}-events"
  visibility_timeout_seconds = var.visibility_timeout_seconds
  message_retention_seconds  = var.message_retention_seconds
  receive_wait_time_seconds  = 20
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = var.max_receive_count
  })
  tags = var.tags
  lifecycle {
    precondition {
      condition     = var.dlq_retention_seconds > var.message_retention_seconds
      error_message = "DLQ retention must exceed source queue retention."
    }
  }
}

resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.events.arn]
  })
}

resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowBronzeBucketNotifications"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.events.arn
      Condition = {
        ArnEquals    = { "aws:SourceArn" = var.bronze_bucket_arn }
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_ecr_repository" "this" {
  name                 = var.name_prefix
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  encryption_configuration { encryption_type = "AES256" }
  image_scanning_configuration { scan_on_push = true }
  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after seven days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 7
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_repository_policy" "lambda" {
  repository = aws_ecr_repository.this.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "LambdaImageRetrieval"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    }]
  })
}

resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_iam_role_policy" "runtime" {
  name = "${var.name_prefix}-runtime"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObjectVersion"], Resource = [local.bronze_objects] },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = [local.silver_objects] },
      {
        Effect    = "Allow"
        Action    = ["s3:ListBucket"]
        Resource  = [var.silver_bucket_arn]
        Condition = { StringLike = { "s3:prefix" = ["${var.silver_prefix}/cisa_kev_snapshots/*"] } }
      },
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], Resource = [aws_sqs_queue.events.arn] },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["${aws_cloudwatch_log_group.this.arn}:*"] }
    ]
  })
}

resource "aws_lambda_function" "this" {
  function_name = var.name_prefix
  role          = aws_iam_role.lambda.arn
  package_type  = "Image"
  image_uri     = var.image_uri
  architectures = ["arm64"]
  timeout       = var.timeout_seconds
  memory_size   = var.memory_size_mb
  environment {
    variables = {
      THREATFLOW_AWS_REGION                  = var.aws_region
      THREATFLOW_S3_BRONZE_BUCKET            = var.bronze_bucket_name
      THREATFLOW_S3_BRONZE_PREFIX            = var.bronze_prefix
      THREATFLOW_S3_SILVER_BUCKET            = var.silver_bucket_name
      THREATFLOW_S3_SILVER_PREFIX            = var.silver_prefix
      THREATFLOW_CISA_MINIMUM_RECORD_COUNT   = tostring(var.minimum_record_count)
      THREATFLOW_CISA_MINIMUM_PREVIOUS_RATIO = tostring(var.minimum_previous_ratio)
    }
  }
  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
    log_group             = aws_cloudwatch_log_group.this.name
  }
  tags       = var.tags
  depends_on = [aws_iam_role_policy.runtime, aws_ecr_repository_policy.lambda]
  lifecycle {
    precondition {
      condition = (
        startswith(var.image_uri, "${aws_ecr_repository.this.repository_url}@sha256:") &&
        can(regex("@sha256:[0-9a-f]{64}$", var.image_uri))
      )
      error_message = "image_uri must use an immutable digest from the CISA ECR repository."
    }
    precondition {
      condition     = var.visibility_timeout_seconds >= 6 * var.timeout_seconds
      error_message = "SQS visibility timeout must be at least six times Lambda timeout."
    }
  }
}

resource "aws_lambda_event_source_mapping" "this" {
  event_source_arn                   = aws_sqs_queue.events.arn
  function_name                      = aws_lambda_function.this.function_name
  enabled                            = var.mapping_enabled
  batch_size                         = 1
  maximum_batching_window_in_seconds = 0
  function_response_types            = ["ReportBatchItemFailures"]
  scaling_config { maximum_concurrency = var.maximum_concurrency }
  depends_on = [aws_iam_role_policy.runtime]
}
