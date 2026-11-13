locals {
  event_queue_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBronzeBucketNotifications"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.events.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = replace(var.bronze_bucket_arn, ":s3:::", ":s3:*:*:")
          }
          StringEquals = {
            "aws:SourceAccount" = var.source_account_id
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.events.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })

  dlq_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.dlq.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = var.dlq_name
  fifo_queue                = false
  message_retention_seconds = var.dlq_message_retention_seconds
  sqs_managed_sse_enabled   = true

  tags = merge(var.tags, {
    Name     = var.dlq_name
    DataFlow = "epss-bronze-to-silver"
    Purpose  = "dead-letter-queue"
  })
}

resource "aws_sqs_queue" "events" {
  name                       = var.queue_name
  fifo_queue                 = false
  visibility_timeout_seconds = var.visibility_timeout_seconds
  message_retention_seconds  = var.message_retention_seconds
  receive_wait_time_seconds  = 20
  # S3 notifications require an unencrypted queue or a customer-managed KMS
  # key whose policy explicitly grants access to s3.amazonaws.com.
  sqs_managed_sse_enabled = false

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = var.max_receive_count
  })

  tags = merge(var.tags, {
    Name     = var.queue_name
    DataFlow = "epss-bronze-to-silver"
    Purpose  = "bronze-object-events"
  })

  lifecycle {
    precondition {
      condition     = var.dlq_message_retention_seconds > var.message_retention_seconds
      error_message = "DLQ retention must be longer than source queue retention."
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
  policy    = local.event_queue_policy
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = local.dlq_policy
}
