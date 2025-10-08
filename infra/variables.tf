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

# Auto-remediation variables for Lambda function
variable "project" {
  description = "Project name for Lambda environment and tagging"
  type        = string
  default     = "driftguard"
}

variable "maintainer_cidr" {
  description = "CIDR block for maintainer access (e.g., '203.0.113.10/32')"
  type        = string
  default     = "203.0.113.10/32"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 256
}

