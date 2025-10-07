package main

deny contains msg if {
    not has_cloudtrail_trails
    msg := "At least one CloudTrail trail must be enabled for security monitoring"
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    trail.enable_logging != true
    msg := sprintf("CloudTrail trail '%s' must be enabled", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    trail.enable_log_file_validation != true
    msg := sprintf("CloudTrail trail '%s' must have log file validation enabled", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    trail.include_global_service_events != true
    msg := sprintf("CloudTrail trail '%s' must include global service events", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    trail.s3_bucket_name == ""
    msg := sprintf("CloudTrail trail '%s' must have S3 bucket configured for log storage", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    trail.s3_bucket_name != ""
    s3_bucket_public(trail.s3_bucket_name)
    msg := sprintf("CloudTrail S3 bucket '%s' must not be publicly accessible", [trail.s3_bucket_name])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    not has_management_events
    msg := sprintf("CloudTrail trail '%s' must record management events", [resource.address])
}

has_cloudtrail_trails() if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
}

s3_bucket_public(bucket_name) if {
    bucket_resource := input.resource_changes[_]
    bucket_resource.type == "aws_s3_bucket"
    bucket_resource.change.after.bucket == bucket_name
    public_access_block := input.resource_changes[_]
    public_access_block.type == "aws_s3_bucket_public_access_block"
    public_access_block.change.after.bucket == bucket_name
    block_config := public_access_block.change.after
    block_config.block_public_acls != true
}

s3_bucket_public(bucket_name) if {
    bucket_resource := input.resource_changes[_]
    bucket_resource.type == "aws_s3_bucket"
    bucket_resource.change.after.bucket == bucket_name
    public_access_block := input.resource_changes[_]
    public_access_block.type == "aws_s3_bucket_public_access_block"
    public_access_block.change.after.bucket == bucket_name
    block_config := public_access_block.change.after
    block_config.block_public_policy != true
}

s3_bucket_public(bucket_name) if {
    bucket_resource := input.resource_changes[_]
    bucket_resource.type == "aws_s3_bucket"
    bucket_resource.change.after.bucket == bucket_name
    public_access_block := input.resource_changes[_]
    public_access_block.type == "aws_s3_bucket_public_access_block"
    public_access_block.change.after.bucket == bucket_name
    block_config := public_access_block.change.after
    block_config.ignore_public_acls != true
}

s3_bucket_public(bucket_name) if {
    bucket_resource := input.resource_changes[_]
    bucket_resource.type == "aws_s3_bucket"
    bucket_resource.change.after.bucket == bucket_name
    public_access_block := input.resource_changes[_]
    public_access_block.type == "aws_s3_bucket_public_access_block"
    public_access_block.change.after.bucket == bucket_name
    block_config := public_access_block.change.after
    block_config.restrict_public_buckets != true
}

has_management_events if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    event_selector := trail.event_selector[_]
    event_selector.include_management_events == true
}