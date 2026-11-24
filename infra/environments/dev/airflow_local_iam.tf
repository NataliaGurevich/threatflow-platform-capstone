locals {
  signin_local_development_policy_arn = "arn:aws:iam::aws:policy/SignInLocalDevelopmentAccess"
}

resource "aws_iam_user" "airflow_local" {
  count = var.create_airflow_local_identity ? 1 : 0

  name          = var.airflow_local_user_name
  path          = "/threatflow/"
  force_destroy = false

  tags = {
    Purpose = "local-airflow-s3-bronze"
  }
}

resource "aws_iam_user_policy_attachment" "airflow_bronze_access" {
  count = var.create_airflow_local_identity ? 1 : 0

  user       = aws_iam_user.airflow_local[0].name
  policy_arn = module.bronze_storage.access_policy_arn
}

resource "aws_iam_user_policy" "airflow_silver_quality_state" {
  count = var.create_airflow_local_identity ? 1 : 0

  name = "threatflow-silver-quality-state"
  user = aws_iam_user.airflow_local[0].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadCommittedCountsForIngestionQuality"
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = [
        "${module.silver_storage.bucket_arn}/${var.silver_prefix}/cisa_kev_snapshots/_latest.json",
        "${module.silver_storage.bucket_arn}/${var.silver_prefix}/epss_scores/score_date=*/_manifest.json",
      ]
    }]
  })
}

resource "aws_iam_user_policy_attachment" "airflow_local_signin" {
  count = var.create_airflow_local_identity ? 1 : 0

  user       = aws_iam_user.airflow_local[0].name
  policy_arn = local.signin_local_development_policy_arn
}
