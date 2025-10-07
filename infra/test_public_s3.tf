terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

resource "aws_s3_bucket" "bad_public" {
  bucket        = "dg-demo-bad-bucket-example-please-change" # not applied, just scanned
  acl           = "public-read"  # <-- HIGH/CRITICAL finding in Checkov
  force_destroy = true
}
