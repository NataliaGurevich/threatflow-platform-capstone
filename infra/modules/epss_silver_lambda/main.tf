locals {
  bronze_object_arn = "${var.bronze_bucket_arn}/${var.bronze_prefix}/source=epss/*"
  silver_object_arn = "${var.silver_bucket_arn}/${var.silver_prefix}/epss_scores/*"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaService"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  runtime_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExactEpssBronzeVersions"
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersion"]
        Resource = [local.bronze_object_arn]
      },
      {
        Sid      = "ReadWriteEpssSilverDataset"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = [local.silver_object_arn]
      },
      {
        Sid      = "ConsumeEpssEventQueue"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = [var.sqs_queue_arn]
      },
      {
        Sid      = "WriteFunctionLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.this.arn}:*"]
      },
    ]
  })

  ecr_repository_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaECRImageRetrievalPolicy"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
      },
    ]
  })
}

resource "aws_iam_role" "this" {
  name               = var.execution_role_name
  assume_role_policy = local.assume_role_policy

  tags = merge(var.tags, {
    Name     = var.execution_role_name
    DataFlow = "epss-bronze-to-silver"
    Purpose  = "lambda-execution-role"
  })
}

resource "aws_iam_role_policy" "runtime" {
  name   = "${var.function_name}-runtime"
  role   = aws_iam_role.this.id
  policy = local.runtime_policy
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name     = "/aws/lambda/${var.function_name}"
    DataFlow = "epss-bronze-to-silver"
    Purpose  = "lambda-runtime-logs"
  })
}

resource "aws_ecr_repository_policy" "lambda" {
  repository = var.ecr_repository_name
  policy     = local.ecr_repository_policy
}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = aws_iam_role.this.arn
  package_type  = "Image"
  image_uri     = var.image_uri
  architectures = ["arm64"]

  memory_size                    = var.memory_size_mb
  timeout                        = var.timeout_seconds
  reserved_concurrent_executions = var.reserved_concurrent_executions
  publish                        = false

  environment {
    variables = {
      THREATFLOW_AWS_REGION       = var.aws_region
      THREATFLOW_S3_BRONZE_BUCKET = var.bronze_bucket_name
      THREATFLOW_S3_BRONZE_PREFIX = var.bronze_prefix
      THREATFLOW_S3_SILVER_BUCKET = var.silver_bucket_name
      THREATFLOW_S3_SILVER_PREFIX = var.silver_prefix
    }
  }

  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
    log_group             = aws_cloudwatch_log_group.this.name
  }

  tags = merge(var.tags, {
    Name     = var.function_name
    DataFlow = "epss-bronze-to-silver"
    Purpose  = "epss-silver-transform"
  })

  depends_on = [
    aws_iam_role_policy.runtime,
    aws_ecr_repository_policy.lambda,
  ]

  lifecycle {
    precondition {
      condition     = startswith(var.image_uri, "${var.ecr_repository_url}@sha256:")
      error_message = "image_uri must use an immutable digest from the configured ECR repository."
    }

    precondition {
      condition     = var.sqs_visibility_timeout_seconds >= (6 * var.timeout_seconds)
      error_message = "The SQS visibility timeout must be at least six times the Lambda timeout."
    }
  }
}

resource "aws_lambda_event_source_mapping" "sqs" {
  event_source_arn = var.sqs_queue_arn
  function_name    = aws_lambda_function.this.function_name
  enabled          = var.event_source_mapping_enabled

  batch_size                         = 1
  maximum_batching_window_in_seconds = 0
  function_response_types            = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = var.event_source_maximum_concurrency
  }

  depends_on = [aws_iam_role_policy.runtime]
}
