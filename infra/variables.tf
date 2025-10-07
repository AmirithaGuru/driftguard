variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "project_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "driftguard"
}

variable "default_tags" {
  description = "Default tags to apply to all resources"
  type        = map(string)
  default = {
    project = "driftguard"
    env     = "sandbox"
  }
}

variable "log_expiration_days" {
  description = "Number of days to retain logs in S3"
  type        = number
  default     = 14
}

