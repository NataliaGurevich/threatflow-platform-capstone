mock_provider "aws" {}

variables {
  repository_name               = "threatflow/epss-silver"
  untagged_image_retention_days = 7
  tags = {
    Environment = "test"
    Project     = "ThreatFlow"
  }
}

run "creates_protected_ecr_repository" {
  command = apply

  assert {
    condition = (
      aws_ecr_repository.this.image_tag_mutability == "IMMUTABLE" &&
      aws_ecr_repository.this.force_delete == false
    )
    error_message = "The ECR repository must use immutable tags and resist forced deletion."
  }

  assert {
    condition = (
      one(aws_ecr_repository.this.encryption_configuration).encryption_type == "AES256" &&
      one(aws_ecr_repository.this.image_scanning_configuration).scan_on_push
    )
    error_message = "The ECR repository must use encryption and scan images on push."
  }

  assert {
    condition = (
      strcontains(aws_ecr_lifecycle_policy.untagged.policy, "\"tagStatus\":\"untagged\"") &&
      strcontains(aws_ecr_lifecycle_policy.untagged.policy, "\"countNumber\":7") &&
      !strcontains(aws_ecr_lifecycle_policy.untagged.policy, "\"tagStatus\":\"tagged\"")
    )
    error_message = "Lifecycle must expire only untagged images after seven days."
  }
}

run "rejects_invalid_repository_name" {
  command = plan

  variables {
    repository_name = "ThreatFlow EPSS"
  }

  expect_failures = [var.repository_name]
}
