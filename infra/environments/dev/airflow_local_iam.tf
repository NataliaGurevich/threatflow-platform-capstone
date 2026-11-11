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

resource "aws_iam_user_policy_attachment" "airflow_local_signin" {
  count = var.create_airflow_local_identity ? 1 : 0

  user       = aws_iam_user.airflow_local[0].name
  policy_arn = local.signin_local_development_policy_arn
}
