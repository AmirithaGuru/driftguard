package main

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    rule := resource.change.after
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.type == "ingress"
    dangerous_port(rule.from_port, rule.to_port)
    msg := sprintf("Security group rule '%s' allows traffic from 0.0.0.0/0 on dangerous port %d-%d", [resource.address, rule.from_port, rule.to_port])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    rule := resource.change.after
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.type == "ingress"
    rule.protocol == "-1"
    msg := sprintf("Security group rule '%s' allows all protocols from 0.0.0.0/0", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    rule := resource.change.after
    rule.ipv6_cidr_blocks[_] == "::/0"
    rule.type == "ingress"
    dangerous_port(rule.from_port, rule.to_port)
    msg := sprintf("Security group rule '%s' allows IPv6 traffic from ::/0 on dangerous port %d-%d", [resource.address, rule.from_port, rule.to_port])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    ingress_rule := resource.change.after.ingress[_]
    ingress_rule.cidr_blocks[_] == "0.0.0.0/0"
    dangerous_port(ingress_rule.from_port, ingress_rule.to_port)
    msg := sprintf("Security group '%s' has inline rule allowing traffic from 0.0.0.0/0 on dangerous port %d-%d", [resource.address, ingress_rule.from_port, ingress_rule.to_port])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    ingress_rule := resource.change.after.ingress[_]
    ingress_rule.cidr_blocks[_] == "0.0.0.0/0"
    ingress_rule.protocol == "-1"
    msg := sprintf("Security group '%s' has inline rule allowing all protocols from 0.0.0.0/0", [resource.address])
}

dangerous_port(from_port, to_port) if {
    from_port <= 22
    to_port >= 22
}

dangerous_port(from_port, to_port) if {
    from_port <= 3389
    to_port >= 3389
}

dangerous_port(from_port, to_port) if {
    from_port == 0
    to_port == 65535
}