mock_provider "aws" {}

variables {
  bucket_name                       = "threatflow-silver-test-123456"
  silver_prefix                     = "silver"
  noncurrent_version_retention_days = 30
  tags = {
    Environment = "test"
    Project     = "ThreatFlow"
  }
}

run "creates_protected_silver_storage" {
  command = apply

  assert {
    condition     = aws_s3_bucket.silver.force_destroy == false
    error_message = "Silver bucket must not allow force deletion."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.silver.block_public_acls &&
      aws_s3_bucket_public_access_block.silver.block_public_policy &&
      aws_s3_bucket_public_access_block.silver.ignore_public_acls &&
      aws_s3_bucket_public_access_block.silver.restrict_public_buckets
    )
    error_message = "All S3 public-access blocks must be enabled."
  }

  assert {
    condition = (
      aws_s3_bucket_ownership_controls.silver.rule[0].object_ownership ==
      "BucketOwnerEnforced"
    )
    error_message = "S3 ACLs must be disabled with BucketOwnerEnforced."
  }

  assert {
    condition = (
      aws_s3_bucket_versioning.silver.versioning_configuration[0].status == "Enabled"
    )
    error_message = "Silver bucket versioning must be enabled."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.silver.rule)
      .apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    )
    error_message = "Silver objects must use default SSE-S3 encryption."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_lifecycle_configuration.silver.rule)
      .abort_incomplete_multipart_upload).days_after_initiation == 7 &&
      one(one(aws_s3_bucket_lifecycle_configuration.silver.rule)
      .noncurrent_version_expiration).noncurrent_days == 30
    )
    error_message = "Silver lifecycle recovery and upload housekeeping is incorrect."
  }

  assert {
    condition = (
      strcontains(aws_s3_bucket_policy.tls_only.policy, "aws:SecureTransport") &&
      strcontains(aws_s3_bucket_policy.tls_only.policy, "DenyInsecureTransport")
    )
    error_message = "Bucket policy must deny requests without TLS."
  }
}

run "rejects_unsafe_prefix" {
  command = plan

  variables {
    silver_prefix = "/silver/"
  }

  expect_failures = [var.silver_prefix]
}
