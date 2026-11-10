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

module "bronze_storage" {
  source = "../../modules/bronze_storage"

  bucket_name                       = var.bucket_name
  bronze_prefix                     = var.bronze_prefix
  noncurrent_version_retention_days = var.noncurrent_version_retention_days

  tags = {
    Owner = "capstone"
  }
}
