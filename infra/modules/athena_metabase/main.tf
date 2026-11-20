locals {
  results_bucket_arn = aws_s3_bucket.results.arn
  results_objects    = "${local.results_bucket_arn}/${var.results_prefix}*"
  gold_bucket_arn    = "arn:aws:s3:::${var.gold_bucket_name}"
  gold_objects       = "${local.gold_bucket_arn}/${var.gold_prefix}/*"
  workgroup_arn      = "arn:aws:athena:${var.aws_region}:${var.account_id}:workgroup/${var.workgroup_name}"
  data_catalog_arn   = "arn:aws:athena:${var.aws_region}:${var.account_id}:datacatalog/AwsDataCatalog"
  glue_catalog_arn   = "arn:aws:glue:${var.aws_region}:${var.account_id}:catalog"
  glue_database_arn  = "arn:aws:glue:${var.aws_region}:${var.account_id}:database/${var.catalog_database}"
  glue_tables_arn    = "arn:aws:glue:${var.aws_region}:${var.account_id}:table/${var.catalog_database}/*"
}

resource "aws_s3_bucket" "results" {
  bucket        = var.results_bucket_name
  force_destroy = false

  tags = merge(var.tags, {
    Name               = var.results_bucket_name
    DataLayer          = "query-results"
    DataClassification = "derived-threat-intelligence"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket = aws_s3_bucket.results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    id     = "expire-athena-query-results"
    status = "Enabled"

    filter {
      prefix = var.results_prefix
    }

    expiration {
      days = var.results_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "results" {
  bucket = aws_s3_bucket.results.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.results.arn,
        "${aws_s3_bucket.results.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.results]
}

resource "aws_athena_workgroup" "metabase" {
  name          = var.workgroup_name
  description   = "Bounded Athena SQL workgroup for ThreatFlow Metabase dashboards."
  force_destroy = false
  state         = "ENABLED"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.bytes_scanned_cutoff_per_query

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }

    result_configuration {
      output_location       = "s3://${aws_s3_bucket.results.id}/${var.results_prefix}"
      expected_bucket_owner = var.account_id

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = var.tags

  depends_on = [
    aws_s3_bucket_ownership_controls.results,
    aws_s3_bucket_server_side_encryption_configuration.results,
  ]
}

resource "aws_iam_user" "metabase" {
  name          = var.metabase_user_name
  force_destroy = false
  tags          = var.tags
}

resource "aws_iam_policy" "metabase" {
  name        = "${var.metabase_user_name}-read-only"
  description = "Run bounded Athena queries over ThreatFlow Gold for Metabase."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "UseDedicatedAthenaWorkgroup"
        Effect = "Allow"
        Action = [
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:GetQueryResultsStream",
          "athena:GetWorkGroup",
          "athena:ListQueryExecutions",
          "athena:StartQueryExecution",
          "athena:StopQueryExecution",
        ]
        Resource = local.workgroup_arn
      },
      {
        Sid    = "ReadAthenaCatalogMetadata"
        Effect = "Allow"
        Action = [
          "athena:GetDataCatalog",
          "athena:GetTableMetadata",
          "athena:ListDatabases",
          "athena:ListTableMetadata",
        ]
        Resource = local.data_catalog_arn
      },
      {
        Sid      = "ListAthenaCatalogs"
        Effect   = "Allow"
        Action   = "athena:ListDataCatalogs"
        Resource = "*"
      },
      {
        Sid    = "ReadGoldCatalog"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:GetPartition",
          "glue:GetPartitions",
          "glue:GetTable",
          "glue:GetTables",
        ]
        Resource = [
          local.glue_catalog_arn,
          local.glue_database_arn,
          local.glue_tables_arn,
        ]
      },
      {
        Sid      = "LocateGoldBucket"
        Effect   = "Allow"
        Action   = "s3:GetBucketLocation"
        Resource = local.gold_bucket_arn
      },
      {
        Sid      = "ListGoldObjects"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = local.gold_bucket_arn
        Condition = {
          StringLike = { "s3:prefix" = [var.gold_prefix, "${var.gold_prefix}/*"] }
        }
      },
      {
        Sid      = "ReadGoldObjects"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = local.gold_objects
      },
      {
        Sid      = "LocateAthenaResultsBucket"
        Effect   = "Allow"
        Action   = "s3:GetBucketLocation"
        Resource = local.results_bucket_arn
      },
      {
        Sid    = "ListAthenaResults"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
        ]
        Resource = local.results_bucket_arn
        Condition = {
          StringLike = { "s3:prefix" = [var.results_prefix, "${var.results_prefix}*"] }
        }
      },
      {
        Sid    = "ReadWriteAthenaResults"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetObject",
          "s3:ListMultipartUploadParts",
          "s3:PutObject",
        ]
        Resource = local.results_objects
      },
    ]
  })

  tags = var.tags
}

resource "aws_iam_user_policy_attachment" "metabase" {
  user       = aws_iam_user.metabase.name
  policy_arn = aws_iam_policy.metabase.arn
}
