mock_provider "aws" {}

variables {
  bronze_bucket_name = "threatflow-bronze-test-123456"
  bronze_prefix      = "bronze"
  queue_arn          = "arn:aws:sqs:eu-central-1:123456789012:threatflow-epss-events-test"
}

run "creates_filtered_epss_object_notification" {
  command = apply

  assert {
    condition = (
      aws_s3_bucket_notification.this.bucket == var.bronze_bucket_name &&
      one(aws_s3_bucket_notification.this.queue).id == "epss-bronze-object-created" &&
      one(aws_s3_bucket_notification.this.queue).queue_arn == var.queue_arn &&
      one(aws_s3_bucket_notification.this.queue).events == toset(["s3:ObjectCreated:*"]) &&
      one(aws_s3_bucket_notification.this.queue).filter_prefix == "bronze/source%3Depss/" &&
      one(aws_s3_bucket_notification.this.queue).filter_suffix == ".csv.gz"
    )
    error_message = "S3 must notify only for EPSS Bronze gzip object-created events."
  }
}

run "rejects_fifo_destination" {
  command = plan

  variables {
    queue_arn = "arn:aws:sqs:eu-central-1:123456789012:events.fifo"
  }

  expect_failures = [var.queue_arn]
}

run "preserves_epss_and_adds_filtered_cisa_notification" {
  command = apply

  variables {
    cisa_queue_arn = "arn:aws:sqs:eu-central-1:123456789012:threatflow-cisa-events-test"
  }

  assert {
    condition = (
      length(aws_s3_bucket_notification.this.queue) == 2 &&
      one([for queue in aws_s3_bucket_notification.this.queue : queue if queue.id == "epss-bronze-object-created"]).filter_prefix == "bronze/source%3Depss/" &&
      one([for queue in aws_s3_bucket_notification.this.queue : queue if queue.id == "cisa-bronze-object-created"]).filter_prefix == "bronze/source%3Dcisa_kev/" &&
      one([for queue in aws_s3_bucket_notification.this.queue : queue if queue.id == "cisa-bronze-object-created"]).filter_suffix == ".json"
    )
    error_message = "The shared bucket notification must preserve EPSS and add filtered CISA events."
  }
}
