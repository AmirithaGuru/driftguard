# DriftGuard Policy-as-Code

This directory contains OPA/Rego policies for DriftGuard that enforce security best practices on
Terraform plans.

## Policy Files

### Core Policies

- **`s3_public_access.rego`** - Ensures S3 buckets have public access blocked
- **`security_groups.rego`** - Prevents dangerous security group rules (0.0.0.0/0 on ports 22/3389)
- **`encryption.rego`** - Requires encryption for S3, EBS, RDS, DynamoDB, and Lambda
- **`cloudtrail.rego`** - Ensures CloudTrail is properly configured and enabled
- **`iam_policies.rego`** - Prevents overly permissive IAM policies

### Exception Management

- **`exceptions.rego`** - Handles policy exceptions with expiration dates
- **`exceptions.yaml`** - Configuration file for temporary policy exceptions

## Usage Instructions

### 1. Generate Terraform Plan

```bash
cd infra
terraform plan -out=plan.bin
terraform show -json plan.bin > plan.json
```

### 2. Run Policy Tests

```bash
# Test all policies
conftest test infra/plan.json -p policy --data policy/exceptions.yaml

# Test specific policy
conftest test infra/plan.json -p policy/s3_public_access.rego

# Test with verbose output
conftest test infra/plan.json -p policy --data policy/exceptions.yaml --output=json
```

### 3. Add Exceptions

Edit `policy/exceptions.yaml` to add temporary exceptions:

```yaml
exceptions:
  - id: EX-006
    owner: YourName
    reason: Temporary exception for testing
    expires: 2024-03-31T23:59:59Z
    resource_id: aws_s3_bucket.test
    violation_type: s3_public_access
```

## Policy Rules Summary

### S3 Public Access

- S3 buckets must have public access blocked
- All 4 public access block flags must be enabled

### Security Groups

- No 0.0.0.0/0 access on ports 22 (SSH) or 3389 (RDP)
- No all-protocol access from 0.0.0.0/0
- No IPv6 ::/0 access on dangerous ports

### Encryption

- S3 buckets must have SSE-S3 or KMS encryption
- EBS volumes and snapshots must be encrypted
- RDS instances and clusters must be encrypted
- DynamoDB tables must have server-side encryption
- Lambda functions with environment variables must use KMS

### CloudTrail

- At least one CloudTrail trail must be enabled
- Log file validation must be enabled
- Global service events must be included
- S3 bucket must be configured
- CloudTrail S3 bucket must not be publicly accessible

### IAM Policies

- No IAM policies with `Action:*` and `Resource:*`
- No dangerous managed policies (AdministratorAccess, PowerUserAccess, etc.)
- No overly permissive inline policies

## Exception Types

- `s3_public_access` - S3 buckets without public access blocking
- `security_group_dangerous_port` - Security groups with dangerous ports
- `ebs_encryption` - Unencrypted EBS volumes
- `cloudtrail_enabled` - Disabled CloudTrail trails
- `iam_overly_permissive` - Overly permissive IAM policies

## Integration with CI/CD

Add to your GitHub Actions workflow:

```yaml
- name: Run DriftGuard Policy Tests
  run: |
    cd infra
    terraform plan -out=plan.bin
    terraform show -json plan.bin > plan.json
    conftest test plan.json -p ../policy --data ../policy/exceptions.yaml
```

## Troubleshooting

### Common Issues

1. **Missing dependencies**: Ensure `conftest` is installed
2. **JSON format**: Make sure Terraform plan is in JSON format
3. **Exception expiration**: Check that exceptions haven't expired
4. **Resource naming**: Ensure resource IDs in exceptions match Terraform addresses

### Debug Commands

```bash
# Check plan format
head -5 infra/plan.json

# Validate exceptions
conftest test policy/exceptions.yaml --policy policy/exceptions.rego

# Test individual policies
conftest test infra/plan.json -p policy/s3_public_access.rego --output=json
```

## Example Output

When policies detect violations, you'll see output like:

```bash
FAIL - plan.json - main - S3 bucket 'aws_s3_bucket.test' must have public access blocked
FAIL - plan.json - main - Security group rule 'aws_security_group_rule.ssh' allows traffic from
0.0.0.0/0 on dangerous port 22-22
FAIL - plan.json - main - EBS volume 'aws_ebs_volume.test' must be encrypted
FAIL - plan.json - main - IAM policy document 'aws_iam_policy_document.test' contains overly
permissive statement

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

## Policy Architecture

The policies use OPA/Rego with the following structure:

- **Package**: All policies use `package main` for compatibility
- **Rules**: Each policy defines `deny contains msg` rules for violations
- **Helpers**: Helper functions for common checks (encryption, dangerous ports, etc.)
- **Exceptions**: Time-based exception system with expiration dates

## Security Best Practices

These policies enforce the following security principles:

1. **Defense in Depth**: Multiple layers of security controls
2. **Least Privilege**: Minimal necessary permissions
3. **Encryption at Rest**: Data protection for sensitive resources
4. **Audit Trail**: Comprehensive logging and monitoring
5. **Public Access Prevention**: Blocking accidental exposure

---

**DriftGuard Policy-as-Code**: Automated Terraform security enforcement
