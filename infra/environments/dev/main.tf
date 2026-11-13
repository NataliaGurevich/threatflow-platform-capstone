provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ThreatFlow"
      Environment = "dev"
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

module "bronze_storage" {
  source = "../../modules/bronze_storage"

  bucket_name                       = var.bucket_name
  bronze_prefix                     = var.bronze_prefix
  noncurrent_version_retention_days = var.noncurrent_version_retention_days

  tags = {
    Owner = "capstone"
  }
}

module "silver_storage" {
  source = "../../modules/silver_storage"

  bucket_name                       = var.silver_bucket_name
  silver_prefix                     = var.silver_prefix
  noncurrent_version_retention_days = var.silver_noncurrent_version_retention_days

  tags = {
    Owner = "capstone"
  }
}

module "epss_silver_queue" {
  source = "../../modules/epss_silver_queue"

  queue_name                    = var.epss_silver_queue_name
  dlq_name                      = var.epss_silver_dlq_name
  bronze_bucket_arn             = module.bronze_storage.bucket_arn
  source_account_id             = data.aws_caller_identity.current.account_id
  visibility_timeout_seconds    = var.epss_silver_queue_visibility_timeout_seconds
  message_retention_seconds     = var.epss_silver_queue_message_retention_seconds
  dlq_message_retention_seconds = var.epss_silver_dlq_message_retention_seconds
  max_receive_count             = var.epss_silver_queue_max_receive_count

  tags = {
    Owner = "capstone"
  }
}

module "epss_silver_image" {
  source = "../../modules/epss_silver_image"

  repository_name               = var.epss_silver_image_repository_name
  untagged_image_retention_days = var.epss_silver_image_untagged_retention_days

  tags = {
    Owner = "capstone"
  }
}

module "epss_silver_lambda" {
  source = "../../modules/epss_silver_lambda"

  function_name                    = var.epss_silver_lambda_function_name
  execution_role_name              = var.epss_silver_lambda_execution_role_name
  image_uri                        = var.epss_silver_lambda_image_uri
  ecr_repository_name              = module.epss_silver_image.repository_name
  ecr_repository_url               = module.epss_silver_image.repository_url
  aws_region                       = var.aws_region
  bronze_bucket_name               = module.bronze_storage.bucket_name
  bronze_bucket_arn                = module.bronze_storage.bucket_arn
  bronze_prefix                    = var.bronze_prefix
  silver_bucket_name               = module.silver_storage.bucket_name
  silver_bucket_arn                = module.silver_storage.bucket_arn
  silver_prefix                    = var.silver_prefix
  memory_size_mb                   = var.epss_silver_lambda_memory_size_mb
  timeout_seconds                  = var.epss_silver_lambda_timeout_seconds
  sqs_queue_arn                    = module.epss_silver_queue.queue_arn
  sqs_visibility_timeout_seconds   = var.epss_silver_queue_visibility_timeout_seconds
  event_source_mapping_enabled     = var.epss_silver_event_source_mapping_enabled
  event_source_maximum_concurrency = var.epss_silver_event_source_maximum_concurrency
  reserved_concurrent_executions   = var.epss_silver_lambda_reserved_concurrency
  log_retention_days               = var.epss_silver_lambda_log_retention_days

  tags = {
    Owner = "capstone"
  }
}

module "epss_bronze_notification" {
  source = "../../modules/epss_bronze_notification"

  bronze_bucket_name = module.bronze_storage.bucket_name
  bronze_prefix      = var.bronze_prefix
  queue_arn          = module.epss_silver_queue.queue_arn

  # S3 sends a destination-validation TestEvent when this resource is created.
  # Ensure the updated handler and active SQS mapping can acknowledge it first.
  depends_on = [
    module.epss_silver_queue,
    module.epss_silver_lambda,
  ]
}
