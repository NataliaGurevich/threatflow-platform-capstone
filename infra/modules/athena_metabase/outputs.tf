output "results_bucket_name" {
  value = aws_s3_bucket.results.id
}

output "results_location" {
  value = "s3://${aws_s3_bucket.results.id}/${var.results_prefix}"
}

output "workgroup_name" {
  value = aws_athena_workgroup.metabase.name
}

output "metabase_user_name" {
  value = aws_iam_user.metabase.name
}

output "metabase_user_arn" {
  value = aws_iam_user.metabase.arn
}

output "metabase_policy_arn" {
  value = aws_iam_policy.metabase.arn
}
