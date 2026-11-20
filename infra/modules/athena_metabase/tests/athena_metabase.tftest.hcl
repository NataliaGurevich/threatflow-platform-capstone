mock_provider "aws" {
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::threatflow-athena-results-test"
      id  = "threatflow-athena-results-test"
    }
  }

  mock_resource "aws_iam_user" {
    defaults = {
      arn  = "arn:aws:iam::123456789012:user/threatflow-metabase-athena-test"
      name = "threatflow-metabase-athena-test"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::123456789012:policy/threatflow-metabase-athena-test-read-only"
    }
  }
}

variables {
  aws_region          = "eu-central-1"
  account_id          = "123456789012"
  results_bucket_name = "threatflow-athena-results-test"
  workgroup_name      = "threatflow-metabase-test"
  metabase_user_name  = "threatflow-metabase-athena-test"
  gold_bucket_name    = "threatflow-gold-test"
}

run "creates_bounded_metabase_athena_access" {
  command = apply

  assert {
    condition = (
      aws_athena_workgroup.metabase.configuration[0].enforce_workgroup_configuration &&
      aws_athena_workgroup.metabase.configuration[0].publish_cloudwatch_metrics_enabled &&
      aws_athena_workgroup.metabase.configuration[0].bytes_scanned_cutoff_per_query == 1000000000 &&
      aws_athena_workgroup.metabase.configuration[0].result_configuration[0].encryption_configuration[0].encryption_option == "SSE_S3"
    )
    error_message = "Metabase workgroup must enforce encrypted results and a per-query scan cutoff."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.results.block_public_policy &&
      aws_s3_bucket_ownership_controls.results.rule[0].object_ownership == "BucketOwnerEnforced" &&
      aws_s3_bucket_lifecycle_configuration.results.rule[0].expiration[0].days == 7
    )
    error_message = "Athena results storage must be private, owner enforced, and short lived."
  }

  assert {
    condition = (
      strcontains(aws_iam_policy.metabase.policy, "athena:GetQueryResultsStream") &&
      strcontains(aws_iam_policy.metabase.policy, "workgroup/threatflow-metabase-test") &&
      strcontains(aws_iam_policy.metabase.policy, "database/threatflow_gold") &&
      strcontains(aws_iam_policy.metabase.policy, "arn:aws:s3:::threatflow-gold-test/gold/*") &&
      !strcontains(aws_iam_policy.metabase.policy, "glue:Create") &&
      !strcontains(aws_iam_policy.metabase.policy, "s3:DeleteObject")
    )
    error_message = "Metabase policy must be read-only for Gold and scoped to its workgroup."
  }
}
