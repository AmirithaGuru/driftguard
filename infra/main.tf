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
    Version = "2012-10-17"
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
        Resource = [
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
  name                          = "driftguard-trail"
  s3_bucket_name                = aws_s3_bucket.logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = false
  is_organization_trail         = false
  enable_logging                = true
  enable_log_file_validation    = true

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
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.default_tags
}

#############################################
# Security Hub
#############################################
resource "aws_securityhub_account" "main" {
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
  enable_default_standards  = false
  # (no tags on this resource)
}

# Subscribe to Foundational Security Best Practices v1.0.0
resource "aws_securityhub_standards_subscription" "foundational" {
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

#############################################
# Auto-Remediation via EventBridge → Lambda
# 
# README: How to deploy and test
# ===============================
# 1. Build Lambda package and apply infrastructure:
#    cd infra
#    make lambda-package
#    aws-vault exec driftguard -- terraform apply
#
# 2. Test S3 remediation:
#    - Create empty test bucket in AWS Console
#    - Make it public (ACL or policy)
#    - Within seconds to ~2 minutes it should flip non-public
#    - Check Lambda logs for JSON entries
#
# 3. Test SG remediation:
#    - Create NEW security group (don't touch existing)
#    - Add inbound rule 0.0.0.0/0 on port 22
#    - Rule should be removed; /32 from MAINTAINER_CIDR added
#    - SG tagged driftguard:quarantined=true
#
# 4. Optional: Security Hub findings if ENABLE_SECURITY_HUB="true"
#
# 5. Commit changes:
#    cd ..
#    git add .
#    git commit -m "feat(lambda): auto-remediate public S3 & wide-open SG; wire EventBridge"
#    git push
#############################################

# Auto-remediation variables are defined in variables.tf

# IAM role for Lambda function with least-privilege permissions
resource "aws_iam_role" "remediator" {
  name = "driftguard-remediator-${random_id.suffix.hex}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.default_tags
}

# Inline IAM policy with minimal required permissions for remediation
resource "aws_iam_role_policy" "remediator" {
  name = "driftguard-remediator-policy"
  role = aws_iam_role.remediator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 permissions for bucket remediation
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging",
          "s3:GetBucketLocation"
        ]
        Resource = "*"
      },
      # S3Control permissions for Public Access Block management
      # Note: PAB operations require s3control: prefix, not s3:
      {
        Effect = "Allow"
        Action = [
          "s3control:PutPublicAccessBlock",
          "s3control:GetPublicAccessBlock"
        ]
        Resource = "*"
      },
      # EC2 permissions for security group remediation
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateTags",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      # CloudWatch Logs permissions
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      # CloudWatch metrics permissions
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      # Security Hub permissions (optional)
      {
        Effect = "Allow"
        Action = [
          "securityhub:BatchImportFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda function for auto-remediation with comprehensive observability
# Emits custom CloudWatch metrics:
# - RemediationSuccess (Count): Successful remediation actions
# - RemediationFailure (Count): Failed remediation attempts  
# - RemediationLatencyMs (Milliseconds): Time taken for remediation
# Uses structured single-line JSON logging for easy parsing in CloudWatch Logs Insights
resource "aws_lambda_function" "remediator" {
  filename         = "remediator.zip"
  function_name    = "driftguard-remediator-${random_id.suffix.hex}"
  role             = aws_iam_role.remediator.arn
  handler          = "remediator.lambda_handler"
  source_code_hash = filebase64sha256("remediator.zip")
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory

  environment {
    variables = {
      PROJECT             = var.project
      METRIC_NAMESPACE    = "DriftGuard"
      MAINTAINER_CIDR     = var.maintainer_cidr
      ENABLE_SECURITY_HUB = "true"
    }
  }

  depends_on = [
    aws_iam_role_policy.remediator,
    aws_cloudwatch_log_group.remediator
  ]

  tags = var.default_tags
}

# CloudWatch Log Group for Lambda function
resource "aws_cloudwatch_log_group" "remediator" {
  name              = "/aws/lambda/driftguard-remediator-${random_id.suffix.hex}"
  retention_in_days = 14

  tags = var.default_tags
}

# EventBridge rule to capture risky CloudTrail events for auto-remediation
# Monitors these specific APIs that could create security vulnerabilities:
# - PutBucketAcl: Bucket ACL changes (could make public)
# - PutBucketPolicy/DeleteBucketPolicy: Bucket policy changes (could allow public access)
# - PutPublicAccessBlock/DeletePublicAccessBlock: PAB configuration changes
# - AuthorizeSecurityGroupIngress: New security group rules (could open dangerous ports)
resource "aws_cloudwatch_event_rule" "remediator" {
  name        = "driftguard-remediator-${random_id.suffix.hex}"
  description = "Capture risky AWS API calls for auto-remediation"

  event_pattern = jsonencode({
    source      = ["aws.s3", "aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock",
        "AuthorizeSecurityGroupIngress"
      ]
    }
  })

  tags = var.default_tags
}

# EventBridge target to invoke Lambda function
resource "aws_cloudwatch_event_target" "remediator" {
  rule      = aws_cloudwatch_event_rule.remediator.name
  target_id = "DriftGuardRemediatorTarget"
  arn       = aws_lambda_function.remediator.arn
}

# Lambda permission for EventBridge to invoke the function
resource "aws_lambda_permission" "remediator" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediator.arn
}
