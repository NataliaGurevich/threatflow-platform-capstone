mock_provider "aws" {}

variables {
  queue_name        = "threatflow-epss-bronze-events-test"
  dlq_name          = "threatflow-epss-bronze-events-test-dlq"
  bronze_bucket_arn = "arn:aws:s3:::threatflow-bronze-test-123456"
  source_account_id = "123456789012"
  max_receive_count = 5
  tags = {
    Environment = "test"
    Project     = "ThreatFlow"
  }
}

run "creates_protected_standard_queue_and_dlq" {
  command = apply

  assert {
    condition = (
      aws_sqs_queue.events.fifo_queue == false &&
      aws_sqs_queue.dlq.fifo_queue == false
    )
    error_message = "The source queue and DLQ must both be Standard queues."
  }

  assert {
    condition = (
      aws_sqs_queue.events.sqs_managed_sse_enabled &&
      aws_sqs_queue.dlq.sqs_managed_sse_enabled
    )
    error_message = "Both queues must use SQS-managed server-side encryption."
  }

  assert {
    condition = (
      aws_sqs_queue.events.visibility_timeout_seconds == 1800 &&
      aws_sqs_queue.events.message_retention_seconds == 345600 &&
      aws_sqs_queue.events.receive_wait_time_seconds == 20 &&
      aws_sqs_queue.dlq.message_retention_seconds == 1209600
    )
    error_message = "Queue visibility, polling, or retention settings are unsafe."
  }

  assert {
    condition = (
      strcontains(aws_sqs_queue.events.redrive_policy, aws_sqs_queue.dlq.arn) &&
      strcontains(aws_sqs_queue.events.redrive_policy, "\"maxReceiveCount\":5")
    )
    error_message = "The source queue must redrive failed messages to the DLQ after five receives."
  }

  assert {
    condition = (
      strcontains(
        aws_sqs_queue_redrive_allow_policy.dlq.redrive_allow_policy,
        "\"redrivePermission\":\"byQueue\"",
      ) &&
      strcontains(
        aws_sqs_queue_redrive_allow_policy.dlq.redrive_allow_policy,
        aws_sqs_queue.events.arn,
      )
    )
    error_message = "The DLQ must accept redrive only from the EPSS event queue."
  }

  assert {
    condition = (
      strcontains(aws_sqs_queue_policy.events.policy, "s3.amazonaws.com") &&
      strcontains(aws_sqs_queue_policy.events.policy, "sqs:SendMessage") &&
      strcontains(aws_sqs_queue_policy.events.policy, var.bronze_bucket_arn) &&
      strcontains(aws_sqs_queue_policy.events.policy, var.source_account_id) &&
      strcontains(aws_sqs_queue_policy.events.policy, "aws:SecureTransport")
    )
    error_message = "The event queue policy must scope S3 delivery and enforce TLS."
  }

  assert {
    condition = (
      strcontains(aws_sqs_queue_policy.dlq.policy, "aws:SecureTransport") &&
      strcontains(aws_sqs_queue_policy.dlq.policy, "DenyInsecureTransport")
    )
    error_message = "The DLQ policy must deny requests without TLS."
  }
}

run "rejects_shorter_dlq_retention" {
  command = plan

  variables {
    dlq_message_retention_seconds = 86400
  }

  expect_failures = [aws_sqs_queue.events]
}
