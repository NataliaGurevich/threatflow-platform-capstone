resource "aws_s3_bucket_notification" "this" {
  bucket = var.bronze_bucket_name

  queue {
    id            = "epss-bronze-object-created"
    queue_arn     = var.queue_arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "${var.bronze_prefix}/source=epss/"
    filter_suffix = ".csv.gz"
  }

  dynamic "queue" {
    for_each = var.cisa_queue_arn == null ? [] : [var.cisa_queue_arn]
    content {
      id            = "cisa-bronze-object-created"
      queue_arn     = queue.value
      events        = ["s3:ObjectCreated:*"]
      filter_prefix = "${var.bronze_prefix}/source=cisa_kev/"
      filter_suffix = ".json"
    }
  }
}
