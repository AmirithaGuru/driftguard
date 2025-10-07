#############################################
# Random suffix for globally-unique S3 name
#############################################
resource "random_id" "suffix" {
  byte_length = 4
}

#############################################
# Logs S3 bucket (CloudTrail)
#############################################
resource "aws_s3_bucket" "logs" {
  bucket = "driftguard-logs-${random_id.suffix.hex}"

  # keep your minimal, safe tags here
  tags = merge(var.default_tags, {
    Name = "driftguard-logs"
  })
}

# Enforce bucket-owner semantics
resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Default encryption (SSE-S3 / AES256)
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Expiration policy (uses your var.log_expiration_days)
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"
    expiration {
      days = var.log_expiration_days
    }
    # required in new API shape; empty filter = all objects
    filter {}
  }
}

# Bucket policy needed by CloudTrail + HTTPS enforcement
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      # CloudTrail must read the bucket ACL
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logs.arn
      },
      # CloudTrail writes log files (owner-full-control ACL)
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      # HTTPS only
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource  = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = false } }
      }
    ]
  })
}

#############################################
# CloudTrail (single-region, management events)
#############################################
resource "aws_cloudtrail" "main" {
  name                       = "driftguard-trail"
  s3_bucket_name             = aws_s3_bucket.logs.bucket
  include_global_service_events = true
  is_multi_region_trail      = false
  is_organization_trail      = false
  enable_logging             = true
  enable_log_file_validation = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  # ensure bucket policy exists first to avoid race/InsufficientS3BucketPolicy
  depends_on = [aws_s3_bucket_policy.logs]

  tags = var.default_tags
}


#############################################
# GuardDuty (import if one already exists)
#############################################
resource "aws_guardduty_detector" "main" {
  enable                        = true
  finding_publishing_frequency  = "FIFTEEN_MINUTES"
  tags                          = var.default_tags
}

#############################################
# Security Hub
#############################################
resource "aws_securityhub_account" "main" {
  auto_enable_controls     = true
  control_finding_generator = "SECURITY_CONTROL"
  enable_default_standards  = false
  # (no tags on this resource)
}

# Subscribe to Foundational Security Best Practices v1.0.0
resource "aws_securityhub_standards_subscription" "foundational" {
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}
