package main

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy_document"
    policy_doc := resource.change.after
    statement := policy_doc.statement[_]
    statement.effect == "Allow"
    statement.action == "*"
    statement.resource == "*"
    dangerous_service(statement)
    msg := sprintf("IAM policy document '%s' contains overly permissive statement allowing all actions on all resources for dangerous service", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role"
    role := resource.change.after
    inline_policy := role.inline_policy[_]
    policy_doc := json.unmarshal(inline_policy.policy)
    statement := policy_doc.statement[_]
    statement.effect == "Allow"
    statement.action == "*"
    statement.resource == "*"
    dangerous_service(statement)
    msg := sprintf("IAM role '%s' has inline policy with overly permissive statement allowing all actions on all resources for dangerous service", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user"
    user := resource.change.after
    inline_policy := user.inline_policy[_]
    policy_doc := json.unmarshal(inline_policy.policy)
    statement := policy_doc.statement[_]
    statement.effect == "Allow"
    statement.action == "*"
    statement.resource == "*"
    dangerous_service(statement)
    msg := sprintf("IAM user '%s' has inline policy with overly permissive statement allowing all actions on all resources for dangerous service", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_group"
    group := resource.change.after
    inline_policy := group.inline_policy[_]
    policy_doc := json.unmarshal(inline_policy.policy)
    statement := policy_doc.statement[_]
    statement.effect == "Allow"
    statement.action == "*"
    statement.resource == "*"
    dangerous_service(statement)
    msg := sprintf("IAM group '%s' has inline policy with overly permissive statement allowing all actions on all resources for dangerous service", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy_attachment"
    attachment := resource.change.after
    dangerous_managed_policy(attachment.policy_arn)
    msg := sprintf("IAM role policy attachment '%s' uses dangerous managed policy '%s'", [resource.address, attachment.policy_arn])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user_policy_attachment"
    attachment := resource.change.after
    dangerous_managed_policy(attachment.policy_arn)
    msg := sprintf("IAM user policy attachment '%s' uses dangerous managed policy '%s'", [resource.address, attachment.policy_arn])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_group_policy_attachment"
    attachment := resource.change.after
    dangerous_managed_policy(attachment.policy_arn)
    msg := sprintf("IAM group policy attachment '%s' uses dangerous managed policy '%s'", [resource.address, attachment.policy_arn])
}

dangerous_service(statement) if {
    statement.action[_] = "iam:*"
}

dangerous_service(statement) if {
    statement.action[_] = "sts:*"
}

dangerous_service(statement) if {
    statement.action[_] = "ec2:*"
}

dangerous_service(statement) if {
    statement.action[_] = "*"
}

dangerous_managed_policy(policy_arn) if {
    policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess"
}

dangerous_managed_policy(policy_arn) if {
    policy_arn == "arn:aws:iam::aws:policy/PowerUserAccess"
}

dangerous_managed_policy(policy_arn) if {
    policy_arn == "arn:aws:iam::aws:policy/IAMFullAccess"
}

dangerous_managed_policy(policy_arn) if {
    policy_arn == "arn:aws:iam::aws:policy/EC2FullAccess"
}