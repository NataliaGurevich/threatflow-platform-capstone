variable "repository_name" {
  description = "Name of the private ECR repository for the EPSS Silver Lambda image."
  type        = string

  validation {
    condition = (
      length(var.repository_name) >= 2 &&
      length(var.repository_name) <= 256 &&
      can(regex("^[a-z0-9]+(?:[._/-][a-z0-9]+)*$", var.repository_name))
    )
    error_message = "repository_name must satisfy the ECR repository naming constraints."
  }
}

variable "untagged_image_retention_days" {
  description = "Days to retain untagged build artifacts before ECR expires them."
  type        = number
  default     = 7

  validation {
    condition = (
      var.untagged_image_retention_days >= 1 &&
      floor(var.untagged_image_retention_days) == var.untagged_image_retention_days
    )
    error_message = "untagged_image_retention_days must be a positive integer."
  }
}

variable "tags" {
  description = "Additional tags applied to the ECR repository."
  type        = map(string)
  default     = {}
}
