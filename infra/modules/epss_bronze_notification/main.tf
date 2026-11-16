resource "aws_s3_bucket_notification" "this" {
  bucket = var.bronze_bucket_name

  queue {
    id        = "epss-bronze-object-created"
    queue_arn = var.queue_arn
    events    = ["s3:ObjectCreated:*"]
    # S3 requires special characters in notification filter values to be
    # percent-encoded. The object key itself continues to contain "source=".
    filter_prefix = "${var.bronze_prefix}/source%3Depss/"
    filter_suffix = ".csv.gz"
  }

  dynamic "queue" {
    for_each = var.cisa_queue_arn == null ? [] : [var.cisa_queue_arn]
    content {
      id            = "cisa-bronze-object-created"
      queue_arn     = queue.value
      events        = ["s3:ObjectCreated:*"]
      filter_prefix = "${var.bronze_prefix}/source%3Dcisa_kev/"
      filter_suffix = ".json"
    }
  }

  dynamic "queue" {
    for_each = var.nvd_queue_arn == null ? [] : [var.nvd_queue_arn]
    content {
      id            = "nvd-window-committed"
      queue_arn     = queue.value
      events        = ["s3:ObjectCreated:*"]
      filter_prefix = "${var.bronze_prefix}/source%3Dnvd/"
      filter_suffix = ".window.json"
    }
  }
}
