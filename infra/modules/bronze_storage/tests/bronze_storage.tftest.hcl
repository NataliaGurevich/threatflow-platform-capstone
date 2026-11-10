mock_provider "aws" {}

variables {
  bucket_name                       = "threatflow-bronze-test-123456"
  bronze_prefix                     = "bronze"
  noncurrent_version_retention_days = 90
  tags = {
    Environment = "test"
    Project     = "ThreatFlow"
  }
}

run "creates_protected_bronze_storage" {
  command = apply

  assert {
    condition     = aws_s3_bucket.bronze.force_destroy == false
    error_message = "Bronze bucket must not allow force deletion."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.bronze.block_public_acls &&
      aws_s3_bucket_public_access_block.bronze.block_public_policy &&
      aws_s3_bucket_public_access_block.bronze.ignore_public_acls &&
      aws_s3_bucket_public_access_block.bronze.restrict_public_buckets
    )
    error_message = "All S3 public-access blocks must be enabled."
  }

  assert {
    condition = (
      aws_s3_bucket_ownership_controls.bronze.rule[0].object_ownership ==
      "BucketOwnerEnforced"
    )
    error_message = "S3 ACLs must be disabled with BucketOwnerEnforced."
  }

  assert {
    condition = (
      aws_s3_bucket_versioning.bronze.versioning_configuration[0].status == "Enabled"
    )
    error_message = "Bronze bucket versioning must be enabled."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.bronze.rule)
      .apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    )
    error_message = "Bronze objects must use default SSE-S3 encryption."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_lifecycle_configuration.bronze.rule)
      .abort_incomplete_multipart_upload).days_after_initiation == 7 &&
      one(one(aws_s3_bucket_lifecycle_configuration.bronze.rule)
      .noncurrent_version_expiration).noncurrent_days == 90
    )
    error_message = "Bronze lifecycle recovery and upload housekeeping is incorrect."
  }

  assert {
    condition = (
      strcontains(aws_s3_bucket_policy.tls_only.policy, "aws:SecureTransport") &&
      strcontains(aws_s3_bucket_policy.tls_only.policy, "DenyInsecureTransport")
    )
    error_message = "Bucket policy must deny requests without TLS."
  }

  assert {
    condition = (
      strcontains(aws_iam_policy.bronze_access.policy, "s3:PutObject") &&
      strcontains(aws_iam_policy.bronze_access.policy, "s3:GetObject") &&
      !strcontains(aws_iam_policy.bronze_access.policy, "s3:DeleteObject") &&
      !strcontains(aws_iam_policy.bronze_access.policy, "s3:ListBucket")
    )
    error_message = "Runtime policy must provide read/write but not delete access."
  }
}

run "rejects_unsafe_prefix" {
  command = plan

  variables {
    bronze_prefix = "/bronze/"
  }

  expect_failures = [var.bronze_prefix]
}
