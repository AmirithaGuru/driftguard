# DriftGuard PR Test Cases

## Purpose

This document contains Terraform HCL snippets to validate DriftGuard's Rego policies via CI/CD. Each
case is designed to test specific security controls and demonstrate expected CI behavior.

## How to Run

### Locally

```bash
# Generate Terraform plan JSON
make plan-json

# Run policy validation
make policy-check
```

### In CI

Create a feature branch with the test case, push to trigger GitHub Actions security workflow.

## Policy Controls Legend

- **C1 S3 PAB**: S3 buckets must have Public Access Block enabled (`policy/s3_public_access.rego`)
- **C2 SG Security**: No `0.0.0.0/0` or `::/0` on ports 22/3389 or protocol `-1`/`all`
  (`policy/security_groups.rego`)
- **C3 KMS Encryption**: S3/EBS/RDS must use KMS encryption, not default AES256
  (`policy/encryption.rego`)
- **C4 CloudTrail**: At least one multi-region CloudTrail enabled, log bucket not public
  (`policy/cloudtrail.rego`)
- **C5 IAM Policies**: No wildcard `Action:*` + `Resource:*` on admin APIs
  (`policy/iam_policies.rego`)

---

## BAD PRs (Violations)

### C1: S3 Public Access Block Violations

#### C1.1: Missing Public Access Block

**Control**: C1 S3 PAB  
**Risk**: Bucket can be made public via ACL or policy  
**Expected CI**: FAIL - "S3 bucket missing Public Access Block"

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

# Missing: aws_s3_bucket_public_access_block resource
```

**Fix**: Add `aws_s3_bucket_public_access_block` with all flags `true`

#### C1.2: Public Access Block Disabled

**Control**: C1 S3 PAB  
**Risk**: Bucket can be made public despite PAB configuration  
**Expected CI**: FAIL - "S3 Public Access Block flags must be enabled"

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  block_public_acls       = false  # FAIL: Should be true
  block_public_policy     = false  # FAIL: Should be true
  ignore_public_acls      = false  # FAIL: Should be true
  restrict_public_buckets = false  # FAIL: Should be true
}
```

**Fix**: Set all PAB flags to `true`

#### C1.3: Public Bucket Policy

**Control**: C1 S3 PAB  
**Risk**: Bucket allows public read access  
**Expected CI**: FAIL - "S3 bucket policy allows public access"

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_policy" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # FAIL: Public access
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.test_bucket.arn}/*"
      }
    ]
  })
}
```

**Fix**: Remove public principal or add condition restrictions

#### C1.4: Public ACL Configuration

**Control**: C1 S3 PAB  
**Risk**: Bucket ACL allows public read  
**Expected CI**: FAIL - "S3 bucket ACL grants public access"

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_acl" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id
  acl    = "public-read"  # FAIL: Public ACL
}
```

**Fix**: Use `private` ACL or remove ACL resource

#### C1.5: Website with Public Access

**Control**: C1 S3 PAB  
**Risk**: Static website hosting can expose content publicly  
**Expected CI**: FAIL - "S3 website configuration with public access"

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_website_configuration" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_policy" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.test_bucket.arn}/*"
      }
    ]
  })
}
```

**Fix**: Add Public Access Block or restrict website access

---

### C2: Security Group Violations

#### C2.1: SSH Open to World

**Control**: C2 SG Security  
**Risk**: SSH access open to entire internet  
**Expected CI**: FAIL - "Security group allows 0.0.0.0/0 on port 22"

```hcl
resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg-"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # FAIL: Open to world
  }
}
```

**Fix**: Restrict to specific CIDR blocks (e.g., office IP)

#### C2.2: RDP Open to World

**Control**: C2 SG Security  
**Risk**: RDP access open to entire internet  
**Expected CI**: FAIL - "Security group allows 0.0.0.0/0 on port 3389"

```hcl
resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg-"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # FAIL: Open to world
  }
}
```

**Fix**: Restrict to specific CIDR blocks

#### C2.3: All Traffic Open

**Control**: C2 SG Security  
**Risk**: All inbound traffic allowed from anywhere  
**Expected CI**: FAIL - "Security group allows 0.0.0.0/0 with protocol all"

```hcl
resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg-"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"  # FAIL: All protocols
    cidr_blocks = ["0.0.0.0/0"]  # FAIL: From anywhere
  }
}
```

**Fix**: Use specific ports and protocols only

#### C2.4: IPv6 Open Access

**Control**: C2 SG Security  
**Risk**: IPv6 traffic open to entire internet  
**Expected CI**: FAIL - "Security group allows ::/0 on port 22"

```hcl
resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg-"

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]  # FAIL: Open to all IPv6
  }
}
```

**Fix**: Restrict IPv6 to specific networks

#### C2.5: Multiple Open Ports

**Control**: C2 SG Security  
**Risk**: Multiple critical ports open to world  
**Expected CI**: FAIL - "Security group allows 0.0.0.0/0 on multiple ports"

```hcl
resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg-"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # FAIL: SSH open
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # FAIL: RDP open
  }
}
```

**Fix**: Restrict both to specific CIDR blocks

---

### C3: KMS Encryption Violations

#### C3.1: S3 Default Encryption

**Control**: C3 KMS Encryption  
**Risk**: Data encrypted with AWS-managed keys instead of customer KMS  
**Expected CI**: FAIL - "S3 bucket uses default encryption instead of KMS"

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # FAIL: Should be aws:kms
    }
  }
}
```

**Fix**: Use `sse_algorithm = "aws:kms"` with `kms_master_key_id`

#### C3.2: Unencrypted EBS Volume

**Control**: C3 KMS Encryption  
**Risk**: Data at rest not encrypted  
**Expected CI**: FAIL - "EBS volume encryption disabled"

```hcl
resource "aws_ebs_volume" "test_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false  # FAIL: Should be true
}
```

**Fix**: Set `encrypted = true` and specify `kms_key_id`

#### C3.3: Unencrypted RDS Instance

**Control**: C3 KMS Encryption  
**Risk**: Database storage not encrypted  
**Expected CI**: FAIL - "RDS instance storage encryption disabled"

```hcl
resource "aws_db_instance" "test_db" {
  identifier = "test-db"
  engine     = "postgres"
  instance_class = "db.t3.micro"
  allocated_storage = 20

  storage_encrypted = false  # FAIL: Should be true
}
```

**Fix**: Set `storage_encrypted = true` and specify `kms_key_id`

#### C3.4: S3 Bucket Without Encryption

**Control**: C3 KMS Encryption  
**Risk**: No encryption configuration on S3 bucket  
**Expected CI**: FAIL - "S3 bucket missing encryption configuration"

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

# Missing: aws_s3_bucket_server_side_encryption_configuration
```

**Fix**: Add encryption configuration with KMS

#### C3.5: EBS Volume Without KMS Key

**Control**: C3 KMS Encryption  
**Risk**: Using default AWS encryption instead of customer KMS  
**Expected CI**: FAIL - "EBS volume missing KMS key specification"

```hcl
resource "aws_ebs_volume" "test_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
  # Missing: kms_key_id
}
```

**Fix**: Specify `kms_key_id` for customer-managed encryption

---

### C4: CloudTrail Violations

#### C4.1: Single Region CloudTrail

**Control**: C4 CloudTrail  
**Risk**: Security events in other regions not logged  
**Expected CI**: FAIL - "CloudTrail not configured for multi-region"

```hcl
resource "aws_cloudtrail" "test_trail" {
  name           = "test-trail"
  s3_bucket_name = aws_s3_bucket.logs.bucket

  is_multi_region_trail = false  # FAIL: Should be true
}
```

**Fix**: Set `is_multi_region_trail = true`

#### C4.2: CloudTrail Log Bucket Public

**Control**: C4 CloudTrail  
**Risk**: CloudTrail logs accessible publicly  
**Expected CI**: FAIL - "CloudTrail log bucket allows public access"

```hcl
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = false  # FAIL: Should be true
  block_public_policy     = false  # FAIL: Should be true
  ignore_public_acls      = false  # FAIL: Should be true
  restrict_public_buckets = false  # FAIL: Should be true
}
```

**Fix**: Enable all Public Access Block flags

#### C4.3: Missing CloudTrail

**Control**: C4 CloudTrail  
**Risk**: No audit trail of API calls  
**Expected CI**: FAIL - "No CloudTrail configuration found"

```hcl
# No aws_cloudtrail resource defined
resource "aws_s3_bucket" "some_bucket" {
  bucket = "some-bucket"
}
```

**Fix**: Add `aws_cloudtrail` resource with multi-region enabled

#### C4.4: CloudTrail Without Logging

**Control**: C4 CloudTrail  
**Risk**: CloudTrail exists but not enabled  
**Expected CI**: FAIL - "CloudTrail logging disabled"

```hcl
resource "aws_cloudtrail" "test_trail" {
  name           = "test-trail"
  s3_bucket_name = aws_s3_bucket.logs.bucket

  is_multi_region_trail = true
  enable_logging        = false  # FAIL: Should be true
}
```

**Fix**: Set `enable_logging = true`

#### C4.5: CloudTrail Log Bucket Policy Public

**Control**: C4 CloudTrail  
**Risk**: CloudTrail log bucket policy allows public access  
**Expected CI**: FAIL - "CloudTrail log bucket policy allows public access"

```hcl
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # FAIL: Public access to logs
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
      }
    ]
  })
}
```

**Fix**: Restrict policy to CloudTrail service only

---

### C5: IAM Policy Violations

#### C5.1: Wildcard Action and Resource

**Control**: C5 IAM Policies  
**Risk**: Overly broad permissions  
**Expected CI**: FAIL - "IAM policy uses wildcard Action and Resource"

```hcl
resource "aws_iam_policy" "test_policy" {
  name = "test-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"      # FAIL: Wildcard action
        Resource = "*"    # FAIL: Wildcard resource
      }
    ]
  })
}
```

**Fix**: Use specific actions and resources

#### C5.2: Admin Namespace Wildcards

**Control**: C5 IAM Policies  
**Risk**: Full admin access to critical services  
**Expected CI**: FAIL - "IAM policy allows wildcard access to admin APIs"

```hcl
resource "aws_iam_policy" "test_policy" {
  name = "test-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:*",        # FAIL: Admin namespace
          "kms:*",        # FAIL: Admin namespace
          "sts:*"         # FAIL: Admin namespace
        ]
        Resource = "*"    # FAIL: Wildcard resource
      }
    ]
  })
}
```

**Fix**: Use specific actions and restrict resources

#### C5.3: EC2 Admin with Wildcards

**Control**: C5 IAM Policies  
**Risk**: Full EC2 administrative access  
**Expected CI**: FAIL - "IAM policy allows wildcard EC2 access"

```hcl
resource "aws_iam_policy" "test_policy" {
  name = "test-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "ec2:*"     # FAIL: Full EC2 access
        Resource = "*"       # FAIL: All resources
      }
    ]
  })
}
```

**Fix**: Use specific EC2 actions and resource ARNs

#### C5.4: S3 Admin with Wildcards

**Control**: C5 IAM Policies  
**Risk**: Full S3 administrative access  
**Expected CI**: FAIL - "IAM policy allows wildcard S3 access"

```hcl
resource "aws_iam_policy" "test_policy" {
  name = "test-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "s3:*"      # FAIL: Full S3 access
        Resource = "*"       # FAIL: All resources
      }
    ]
  })
}
```

**Fix**: Use specific S3 actions and bucket ARNs

#### C5.5: Multiple Admin Services Wildcard

**Control**: C5 IAM Policies  
**Risk**: Administrative access to multiple critical services  
**Expected CI**: FAIL - "IAM policy allows wildcard access to multiple admin services"

```hcl
resource "aws_iam_policy" "test_policy" {
  name = "test-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:*",
          "kms:*",
          "ec2:*",
          "s3:*",
          "rds:*"
        ]
        Resource = "*"
      }
    ]
  })
}
```

**Fix**: Break into specific policies with limited actions and resources

---

## GOOD PRs (Compliant Examples)

### C1: S3 Public Access Block - Compliant

#### C1.G1: Proper PAB Configuration

**Control**: C1 S3 PAB  
**Rationale**: All PAB flags enabled to prevent public access  
**Expected CI**: PASS

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

#### C1.G2: Private Bucket with Proper ACL

**Control**: C1 S3 PAB  
**Rationale**: Private ACL with PAB enabled  
**Expected CI**: PASS

```hcl
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_acl" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

---

### C2: Security Group - Compliant

#### C2.G1: Restricted SSH Access

**Control**: C2 SG Security  
**Rationale**: SSH access limited to office IP range  
**Expected CI**: PASS

```hcl
resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg-"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]  # PASS: Office network
  }
}
```

#### C2.G2: HTTPS Only Public Access

**Control**: C2 SG Security  
**Rationale**: Only HTTPS allowed from anywhere (common for web apps)  
**Expected CI**: PASS

```hcl
resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg-"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # PASS: HTTPS is acceptable
  }
}
```

---

### C3: KMS Encryption - Compliant

#### C3.G1: S3 with KMS Encryption

**Control**: C3 KMS Encryption  
**Rationale**: S3 bucket encrypted with customer KMS key  
**Expected CI**: PASS

```hcl
resource "aws_kms_key" "s3_key" {
  description = "KMS key for S3 encryption"
}

resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
```

#### C3.G2: EBS with KMS Encryption

**Control**: C3 KMS Encryption  
**Rationale**: EBS volume encrypted with customer KMS key  
**Expected CI**: PASS

```hcl
resource "aws_kms_key" "ebs_key" {
  description = "KMS key for EBS encryption"
}

resource "aws_ebs_volume" "test_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs_key.arn
}
```

---

### C4: CloudTrail - Compliant

#### C4.G1: Multi-Region CloudTrail

**Control**: C4 CloudTrail  
**Rationale**: Multi-region CloudTrail with secure log bucket  
**Expected CI**: PASS

```hcl
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "main_trail" {
  name           = "main-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket

  is_multi_region_trail = true
  enable_logging        = true
}
```

---

### C5: IAM Policies - Compliant

#### C5.G1: Specific Actions and Resources

**Control**: C5 IAM Policies  
**Rationale**: Limited permissions for specific resources  
**Expected CI**: PASS

```hcl
resource "aws_iam_policy" "test_policy" {
  name = "test-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::specific-bucket/*"
      }
    ]
  })
}
```

#### C5.G2: IAM Role for EC2 with Limited Permissions

**Control**: C5 IAM Policies  
**Rationale**: EC2 role with specific, limited permissions  
**Expected CI**: PASS

```hcl
resource "aws_iam_role" "ec2_role" {
  name = "ec2-limited-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "ec2-limited-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::app-bucket",
          "arn:aws:s3:::app-bucket/*"
        ]
      }
    ]
  })
}
```

---

## EXCEPTIONS (Time-Boxed Waivers)

### EX1: Temporary Public S3 for Migration

**Control**: C1 S3 PAB  
**Rationale**: Temporary public access needed for data migration  
**Expected CI**: PASS (waived)  
**Exception Expires**: 2025-12-31T23:59:59Z

**PR Snippet:**

```hcl
resource "aws_s3_bucket" "migration_bucket" {
  bucket = "migration-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "migration_bucket" {
  bucket = aws_s3_bucket.migration_bucket.id

  block_public_acls       = false  # FAIL: Would normally fail
  block_public_policy     = false  # FAIL: Would normally fail
  ignore_public_acls      = false  # FAIL: Would normally fail
  restrict_public_buckets = false  # FAIL: Would normally fail
}
```

**Matching `policy/exceptions.yaml` entry:**

```yaml
exceptions:
  - id: "EX-MIGRATION-001"
    owner: "devops-team"
    reason: "Temporary public access for data migration from legacy system"
    expires: "2025-12-31T23:59:59Z"
    resource_id: "aws_s3_bucket_public_access_block.migration_bucket"
    controls: ["C1"]
```

**After Expiry**: Same PR will fail once `expires < now()` - requires new exception or proper
remediation.

### EX2: Emergency Security Group for Incident Response

**Control**: C2 SG Security  
**Rationale**: Emergency SSH access needed for incident response  
**Expected CI**: PASS (waived)  
**Exception Expires**: 2025-11-15T06:00:00Z

**PR Snippet:**

```hcl
resource "aws_security_group" "incident_response" {
  name_prefix = "incident-response-"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # FAIL: Would normally fail
  }
}
```

**Matching `policy/exceptions.yaml` entry:**

```yaml
exceptions:
  - id: "EX-INCIDENT-002"
    owner: "security-team"
    reason: "Emergency SSH access for incident response - active security incident"
    expires: "2025-11-15T06:00:00Z"
    resource_id: "aws_security_group.incident_response"
    controls: ["C2"]
```

### EX3: Development Environment Admin Policy

**Control**: C5 IAM Policies  
**Rationale**: Development environment needs broad permissions for testing  
**Expected CI**: PASS (waived)  
**Exception Expires**: 2025-12-01T00:00:00Z

**PR Snippet:**

```hcl
resource "aws_iam_policy" "dev_admin_policy" {
  name = "dev-admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"      # FAIL: Would normally fail
        Resource = "*"    # FAIL: Would normally fail
      }
    ]
  })
}
```

**Matching `policy/exceptions.yaml` entry:**

```yaml
exceptions:
  - id: "EX-DEV-003"
    owner: "dev-team"
    reason: "Development environment requires broad permissions for testing and experimentation"
    expires: "2025-12-01T00:00:00Z"
    resource_id: "aws_iam_policy.dev_admin_policy"
    controls: ["C5"]
```

---

## Runbook

### Local Testing

```bash
# 1. Navigate to infra directory
cd infra

# 2. Generate Terraform plan JSON
make plan-json

# 3. Run policy validation
make policy-check

# 4. Review results
# - Check for expected PASS/FAIL outcomes
# - Verify deny messages match expected format
# - Confirm exception handling works correctly
```

### CI Testing

1. Create feature branch: `git checkout -b test/pr-case-{case-name}`
2. Add test case to appropriate Terraform file
3. Commit and push: `git push origin test/pr-case-{case-name}`
4. Open PR and observe GitHub Actions workflow
5. Verify CI results match expected outcomes

### Metrics Collection

| Case Name | Control | Expected | Actual | False Positive | Time (mins) | Notes     |
| --------- | ------- | -------- | ------ | -------------- | ----------- | --------- |
| C1.1      | C1      | FAIL     |        |                |             |           |
| C1.2      | C1      | FAIL     |        |                |             |           |
| C2.1      | C2      | FAIL     |        |                |             |           |
| C3.1      | C3      | FAIL     |        |                |             |           |
| C4.1      | C4      | FAIL     |        |                |             |           |
| C5.1      | C5      | FAIL     |        |                |             |           |
| EX1       | C1      | PASS     |        |                |             | Exception |
| C1.G1     | C1      | PASS     |        |                |             |           |
| C2.G1     | C2      | PASS     |        |                |             |           |

### Weekly Summary Template

**Week of**: [Date]  
**Total Cases Tested**: [Number]  
**Expected Failures**: [Number]  
**Actual Failures**: [Number]  
**False Positives**: [Number]  
**False Negatives**: [Number]  
**Average Review Time**: [Minutes]  
**Policy Coverage**: [Percentage]

**Notes**:

- [Any issues found]
- [Performance observations]
- [Policy improvements needed]
