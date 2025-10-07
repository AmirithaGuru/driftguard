provider "aws" {
  region = var.aws_region

  # apply consistent tags to resources that support it
  default_tags {
    tags = var.default_tags
  }
}

# Helpers for dynamic ARNs/regions
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
