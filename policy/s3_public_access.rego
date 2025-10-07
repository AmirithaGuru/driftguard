package main

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not has_public_access_block(resource)
    msg := sprintf("S3 bucket '%s' must have public access blocked", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    public_access_block := resource.change.after
    public_access_block.block_public_acls != true
    msg := sprintf("S3 bucket public access block '%s' must block public ACLs", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    public_access_block := resource.change.after
    public_access_block.block_public_policy != true
    msg := sprintf("S3 bucket public access block '%s' must block public policies", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    public_access_block := resource.change.after
    public_access_block.ignore_public_acls != true
    msg := sprintf("S3 bucket public access block '%s' must ignore public ACLs", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    public_access_block := resource.change.after
    public_access_block.restrict_public_buckets != true
    msg := sprintf("S3 bucket public access block '%s' must restrict public buckets", [resource.address])
}

has_public_access_block(bucket_resource) if {
    public_access_block := input.resource_changes[_]
    public_access_block.type == "aws_s3_bucket_public_access_block"
    public_access_block.change.after.bucket == bucket_resource.change.after.bucket
}