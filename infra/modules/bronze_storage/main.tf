locals {
  object_arn = "${aws_s3_bucket.bronze.arn}/${var.bronze_prefix}/*"

  tls_only_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.bronze.arn,
          "${aws_s3_bucket.bronze.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })

  bronze_access_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadWriteBronzeObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectAttributes",
          "s3:GetObjectVersion",
          "s3:PutObject",
        ]
        Resource = local.object_arn
      },
      {
        Sid      = "ResolveMissingNvdCheckpoint"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.bronze.arn]
        Condition = {
          StringLike = {
            "s3:prefix" = ["${var.bronze_prefix}/_control/nvd/*"]
          }
        }
      },
    ]
  })
}

resource "aws_s3_bucket" "bronze" {
  bucket        = var.bucket_name
  force_destroy = false

  tags = merge(var.tags, {
    Name               = var.bucket_name
    DataLayer          = "bronze"
    DataClassification = "public-threat-intelligence"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "bronze" {
  bucket = aws_s3_bucket.bronze.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "bronze" {
  bucket = aws_s3_bucket.bronze.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "bronze" {
  bucket = aws_s3_bucket.bronze.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bronze" {
  bucket = aws_s3_bucket.bronze.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }

    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "bronze" {
  bucket = aws_s3_bucket.bronze.id

  rule {
    id     = "bronze-recovery-and-upload-housekeeping"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.bronze]
}

resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.bronze.id
  policy = local.tls_only_policy

  depends_on = [aws_s3_bucket_public_access_block.bronze]
}

resource "aws_iam_policy" "bronze_access" {
  name_prefix = "threatflow-bronze-access-"
  description = "Least-privilege object access to the ThreatFlow Bronze prefix"
  policy      = local.bronze_access_policy

  tags = var.tags
}
