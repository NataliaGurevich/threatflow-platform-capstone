output "repository_name" {
  description = "Name of the EPSS Silver image repository."
  value       = aws_ecr_repository.this.name
}

output "repository_arn" {
  description = "ARN of the EPSS Silver image repository."
  value       = aws_ecr_repository.this.arn
}

output "repository_url" {
  description = "Registry URL used to tag and push the EPSS Silver image."
  value       = aws_ecr_repository.this.repository_url
}
