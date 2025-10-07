package policy.exceptions

import data.exceptions

has_valid_exception(resource_id, violation_type) {
    exception := data.exceptions.exceptions[_]
    exception.resource_id == resource_id
    exception.violation_type == violation_type
    exception.expires > time.now_ns() / 1000000000
    has_required_fields(exception)
}

has_required_fields(exception) {
    exception.id != ""
    exception.owner != ""
    exception.reason != ""
    exception.expires != ""
    exception.resource_id != ""
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not has_public_access_block(resource)
    not has_valid_exception(resource.address, "s3_public_access")
    msg := sprintf("S3 bucket '%s' must have public access blocked", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    rule := resource.change.after
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.type == "ingress"
    dangerous_port(rule.from_port, rule.to_port)
    not has_valid_exception(resource.address, "security_group_dangerous_port")
    msg := sprintf("Security group rule '%s' allows traffic from 0.0.0.0/0 on dangerous port %d-%d", [resource.address, rule.from_port, rule.to_port])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    volume := resource.change.after
    volume.encrypted != true
    not has_valid_exception(resource.address, "ebs_encryption")
    msg := sprintf("EBS volume '%s' must be encrypted", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after
    trail.enable_logging != true
    not has_valid_exception(resource.address, "cloudtrail_enabled")
    msg := sprintf("CloudTrail trail '%s' must be enabled", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy_document"
    policy_doc := resource.change.after
    statement := policy_doc.statement[_]
    statement.effect == "Allow"
    statement.action == "*"
    statement.resource == "*"
    dangerous_service(statement)
    not has_valid_exception(resource.address, "iam_overly_permissive")
    msg := sprintf("IAM policy document '%s' contains overly permissive statement", [resource.address])
}

has_public_access_block(bucket_resource) {
    public_access_block := input.resource_changes[_]
    public_access_block.type == "aws_s3_bucket_public_access_block"
    public_access_block.change.after.bucket == bucket_resource.change.after.bucket
}

dangerous_port(from_port, to_port) {
    from_port <= 22
    to_port >= 22
}

dangerous_port(from_port, to_port) {
    from_port <= 3389
    to_port >= 3389
}

dangerous_port(from_port, to_port) {
    from_port == 0
    to_port == 65535
}

dangerous_service(statement) {
    statement.action[_] = "iam:*"
}

dangerous_service(statement) {
    statement.action[_] = "sts:*"
}

dangerous_service(statement) {
    statement.action[_] = "ec2:*"
}

dangerous_service(statement) {
    statement.action[_] = "*"
}