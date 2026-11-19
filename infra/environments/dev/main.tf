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

module "cisa_silver_runtime" {
  source = "../../modules/cisa_silver_runtime"

  name_prefix            = "threatflow-cisa-silver-dev"
  image_uri              = var.cisa_silver_lambda_image_uri
  aws_region             = var.aws_region
  account_id             = data.aws_caller_identity.current.account_id
  bronze_bucket_name     = module.bronze_storage.bucket_name
  bronze_bucket_arn      = module.bronze_storage.bucket_arn
  bronze_prefix          = var.bronze_prefix
  silver_bucket_name     = module.silver_storage.bucket_name
  silver_bucket_arn      = module.silver_storage.bucket_arn
  silver_prefix          = var.silver_prefix
  mapping_enabled        = var.cisa_silver_event_source_mapping_enabled
  minimum_record_count   = var.cisa_minimum_record_count
  minimum_previous_ratio = var.cisa_minimum_previous_ratio

  tags = {
    Owner    = "capstone"
    DataFlow = "cisa-bronze-to-silver"
  }
}

module "nvd_silver_runtime" {
  source = "../../modules/nvd_silver_runtime"

  name_prefix        = "threatflow-nvd-silver-dev"
  image_uri          = var.nvd_silver_lambda_image_uri
  aws_region         = var.aws_region
  account_id         = data.aws_caller_identity.current.account_id
  bronze_bucket_name = module.bronze_storage.bucket_name
  bronze_bucket_arn  = module.bronze_storage.bucket_arn
  bronze_prefix      = var.bronze_prefix
  silver_bucket_name = module.silver_storage.bucket_name
  silver_bucket_arn  = module.silver_storage.bucket_arn
  silver_prefix      = var.silver_prefix
  mapping_enabled    = var.nvd_silver_event_source_mapping_enabled

  tags = {
    Owner    = "capstone"
    DataFlow = "nvd-bronze-to-silver"
  }
}

module "epss_bronze_notification" {
  source = "../../modules/epss_bronze_notification"

  bronze_bucket_name = module.bronze_storage.bucket_name
  bronze_prefix      = var.bronze_prefix
  queue_arn          = module.epss_silver_queue.queue_arn
  cisa_queue_arn     = module.cisa_silver_runtime.queue_arn
  nvd_queue_arn      = module.nvd_silver_runtime.queue_arn

  # S3 sends a destination-validation TestEvent when this resource is created.
  # Ensure the updated handler and active SQS mapping can acknowledge it first.
  depends_on = [
    module.epss_silver_queue,
    module.epss_silver_lambda,
    module.cisa_silver_runtime,
    module.nvd_silver_runtime,
  ]
}

module "pipeline_observability" {
  source = "../../modules/pipeline_observability"

  name_prefix         = "threatflow-dev"
  aws_region          = var.aws_region
  cisa_log_group_name = module.cisa_silver_runtime.log_group_name
  epss_log_group_name = module.epss_silver_lambda.log_group_name
  cisa_function_name  = module.cisa_silver_runtime.function_name
  epss_function_name  = module.epss_silver_lambda.function_name
  cisa_queue_name     = module.cisa_silver_runtime.queue_name
  epss_queue_name     = module.epss_silver_queue.queue_name
  cisa_dlq_name       = module.cisa_silver_runtime.dlq_name
  epss_dlq_name       = module.epss_silver_queue.dlq_name
  nvd_log_group_name  = module.nvd_silver_runtime.log_group_name
  nvd_function_name   = module.nvd_silver_runtime.function_name
  nvd_queue_name      = module.nvd_silver_runtime.queue_name
  nvd_dlq_name        = module.nvd_silver_runtime.dlq_name

  tags = {
    Owner   = "capstone"
    Purpose = "bronze-to-silver-observability"
  }
}

module "gold_runtime" {
  count  = var.create_gold_daily_runtime ? 1 : 0
  source = "../../modules/gold_runtime"

  name_prefix          = "threatflow-vulnerability-priority-gold-dev"
  aws_region           = var.aws_region
  account_id           = data.aws_caller_identity.current.account_id
  silver_bucket_name   = module.silver_storage.bucket_name
  silver_bucket_arn    = module.silver_storage.bucket_arn
  silver_prefix        = var.silver_prefix
  gold_bucket_name     = var.gold_bucket_name
  gold_prefix          = var.gold_prefix
  script_s3_uri        = var.gold_glue_script_s3_uri
  wheel_s3_uri         = var.gold_glue_wheel_s3_uri
  snapshot_type        = "RECONSTRUCTED"
  nvd_history_complete = false
  max_input_lag_days   = var.gold_max_input_lag_days
  schedule_expression  = var.gold_schedule_expression
  schedule_timezone    = var.gold_schedule_timezone
  schedule_enabled     = var.gold_schedule_enabled

  tags = {
    Owner    = "capstone"
    DataFlow = "silver-to-gold"
  }
}
