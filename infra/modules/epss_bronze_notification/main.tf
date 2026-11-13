resource "aws_s3_bucket_notification" "this" {
  bucket = var.bronze_bucket_name

  queue {
    id            = "epss-bronze-object-created"
    queue_arn     = var.queue_arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "${var.bronze_prefix}/source=epss/"
    filter_suffix = ".csv.gz"
  }
}
