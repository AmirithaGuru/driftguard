package main

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    encryption_config := resource.change.after
    not has_valid_s3_encryption(encryption_config)
    msg := sprintf("S3 bucket encryption '%s' must use KMS or SSE-S3 encryption", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not has_s3_encryption_config(resource)
    msg := sprintf("S3 bucket '%s' must have server-side encryption configured", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    volume := resource.change.after
    volume.encrypted != true
    msg := sprintf("EBS volume '%s' must be encrypted", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_snapshot"
    snapshot := resource.change.after
    snapshot.encrypted != true
    msg := sprintf("EBS snapshot '%s' must be encrypted", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    db_instance := resource.change.after
    db_instance.storage_encrypted != true
    msg := sprintf("RDS instance '%s' must be encrypted", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_rds_cluster"
    db_cluster := resource.change.after
    db_cluster.storage_encrypted != true
    msg := sprintf("RDS cluster '%s' must be encrypted", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    table := resource.change.after
    not has_valid_dynamodb_encryption(table)
    msg := sprintf("DynamoDB table '%s' must have server-side encryption enabled", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    lambda_func := resource.change.after
    has_environment_variables(lambda_func)
    lambda_func.kms_key_arn == ""
    msg := sprintf("Lambda function '%s' with environment variables must use KMS encryption", [resource.address])
}

has_valid_s3_encryption(encryption_config) if {
    rule := encryption_config.rule[_]
    rule.apply_server_side_encryption_by_default.sse_algorithm == "AES256"
}

has_valid_s3_encryption(encryption_config) if {
    rule := encryption_config.rule[_]
    rule.apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}

has_s3_encryption_config(bucket_resource) if {
    encryption_config := input.resource_changes[_]
    encryption_config.type == "aws_s3_bucket_server_side_encryption_configuration"
    encryption_config.change.after.bucket == bucket_resource.change.after.bucket
}

has_valid_dynamodb_encryption(table) if {
    table.server_side_encryption.kms_key_id != ""
}

has_valid_dynamodb_encryption(table) if {
    table.server_side_encryption.enabled == true
}

has_environment_variables(lambda_func) if {
    lambda_func.environment.variables != {}
}