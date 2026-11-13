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
      one(aws_s3_bucket_notification.this.queue).filter_prefix == "bronze/source=epss/" &&
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
