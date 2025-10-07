output "s3_logs_bucket_name" {
  description = "Name of the S3 bucket used for logs"
  value       = aws_s3_bucket.logs.bucket
}

output "s3_logs_bucket_arn" {
  description = "ARN of the S3 bucket used for logs"
  value       = aws_s3_bucket.logs.arn
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = aws_cloudtrail.main.name
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.main.id
}

output "securityhub_account_arn" {
  description = "ARN of the Security Hub account"
  value       = aws_securityhub_account.main.arn
}

output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = data.aws_region.current.name
}

output "aws_partition" {
  description = "AWS partition (aws, aws-cn, aws-us-gov)"
  value       = data.aws_partition.current.partition
}