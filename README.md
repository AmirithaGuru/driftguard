# 🛡️ DriftGuard: Policy-Gated IaC + Auto-Remediation

**DriftGuard** is a guardrails-as-code platform for AWS that enforces security policies at two critical checkpoints: **pre-merge prevention** using OPA/Rego policies on `terraform plan` JSON to block risky infrastructure changes in CI, and **near real-time auto-remediation** via CloudTrail → EventBridge → Lambda to detect and fix manual drift within seconds. The platform emits structured JSON logs and custom CloudWatch metrics (MTTD, MTTR, prevention rates) and optionally publishes findings to Security Hub, giving teams both proactive gates and reactive guardrails with full observability.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PREVENTION (Pre-Merge)                                                 │
│                                                                          │
│  Developer → PR → GitHub Actions CI                                     │
│                    │                                                     │
│                    ├─→ terraform plan -out=plan.bin                     │
│                    ├─→ terraform show -json plan.bin > plan.json       │
│                    ├─→ conftest test plan.json -p policy/              │
│                    │   (OPA/Rego: C1..C5 controls + exceptions.yaml)   │
│                    ├─→ checkov -d infra --compact                       │
│                    │                                                     │
│                    └─→ ✅ PASS → Merge  |  ❌ FAIL → Block PR           │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  AUTO-REMEDIATION (Post-Deployment Drift)                               │
│                                                                          │
│  Manual Console Change → CloudTrail (Management Events)                 │
│           │                                                              │
│           └─→ EventBridge Rule                                          │
│                (PutBucketAcl, PutBucketPolicy, AuthorizeSecurityGroup*) │
│                    │                                                     │
│                    └─→ Lambda (Python 3.11 remediator)                  │
│                         ├─→ S3 Playbook:                                │
│                         │    - Enable Public Access Block (all 4 flags) │
│                         │    - Sanitize bucket policy (remove public)   │
│                         │    - Tag: driftguard:remediated=true          │
│                         │                                                │
│                         ├─→ SG Playbook:                                │
│                         │    - Revoke 0.0.0.0/0 on ports 22/3389        │
│                         │    - Add maintainer /32 CIDR                  │
│                         │    - Tag: driftguard:quarantined=true         │
│                         │                                                │
│                         ├─→ CloudWatch Logs (structured JSON)           │
│                         ├─→ CloudWatch Metrics (MTTD, MTTR, Success)    │
│                         └─→ Security Hub (optional findings)            │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  OBSERVABILITY                                                           │
│                                                                          │
│  CloudWatch Logs Insights → Query structured JSON logs                  │
│  CloudWatch Metrics → RemediationSuccess, RemediationLatencyMs          │
│  Security Hub → Aggregated findings dashboard                           │
│  /metrics/collect.py → KPI reports (prevention rate, MTTD/MTTR p50/p95) │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Enforced Security Controls

DriftGuard implements **five critical security controls** validated in CI and enforced at runtime:

- **C1: S3 Public Access Block** — All S3 buckets must have Public Access Block enabled (all 4 flags: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`). Bucket policies with `"Principal": "*"` are denied unless explicitly waived.

- **C2: Security Group Ingress Restrictions** — Denies security groups with `0.0.0.0/0` or `::/0` on high-risk ports (22 SSH, 3389 RDP) or protocol `-1` (all traffic). Only specific maintainer CIDRs are allowed.

- **C3: Encryption at Rest (KMS)** — Requires KMS-based encryption for S3 buckets, EBS volumes, and RDS instances. Default AWS-managed keys (AES256) are rejected in favor of customer-managed KMS keys for auditability.

- **C4: CloudTrail Baseline** — Enforces at least one multi-region CloudTrail with log file validation enabled. Trail log buckets must have Public Access Block enabled and must not have public bucket policies.

- **C5: IAM Least-Privilege** — Blocks IAM policies with `Action: "*"` + `Resource: "*"` combinations or wildcard actions on sensitive namespaces (`iam:*`, `kms:*`, `sts:*`) with `Resource: "*"`. Requires scoped permissions.

---

## 🤖 Automated Remediation Playbooks

DriftGuard's Lambda remediator executes **idempotent playbooks** triggered by CloudTrail events:

### S3 Playbook (Public Bucket Detection)
**Trigger Events**: `PutBucketAcl`, `PutBucketPolicy`, `DeleteBucketPolicy`, `PutPublicAccessBlock`, `DeletePublicAccessBlock`

**Actions**:
1. Call `s3control:PutPublicAccessBlock` to enforce all 4 PAB flags
2. Retrieve and sanitize bucket policy: remove any statements with `"Principal": "*"` allowing public access
3. Apply tag `driftguard:remediated=true` with timestamp
4. Emit structured log and CloudWatch metric `RemediationSuccess` or `RemediationFailure`

**MTTR Target**: < 15 seconds (p95)

### Security Group Playbook (Open Ingress Detection)
**Trigger Events**: `AuthorizeSecurityGroupIngress`

**Actions**:
1. Describe security group to identify risky ingress rules
2. Revoke any rules with `0.0.0.0/0` or `::/0` on ports 22, 3389, or protocol `-1`
3. Authorize maintainer CIDR (from `MAINTAINER_CIDR` env var) on ports 22 and 3389
4. Apply tag `driftguard:quarantined=true` with timestamp
5. Emit structured log and CloudWatch metric

**MTTR Target**: < 20 seconds (p95)

---

## 📊 Current Performance Metrics

| KPI | Value |
|-----|-------|
| **Prevention Rate** | 100.0% (2/2) |
| **False-Positive %** | N/A (0/1) |
| **CI Overhead p50/p95 (s)** | 42.1 / 45.3 |
| **MTTD p50/p95 (s)** | 45.1 / 45.1 |
| **MTTR p50/p95 (s)** | 27.7 / 27.7 |
| **High/Critical Density** | 0.16 → 0.00 (-0.16) |

> **Note**: Metrics generated from simulation data. Run `python3 metrics/collect.py` after collecting real CI and drift data.

**Metric Definitions**:
- **Prevention Rate**: % of bad PRs blocked by CI security checks
- **False-Positive %**: % of good PRs incorrectly flagged
- **CI Overhead**: Time spent on security validation (p50/p95)
- **MTTD**: Mean Time To Detection (event observed - change made)
- **MTTR**: Mean Time To Remediation (fix complete - event observed)
- **Security Density**: High/Critical findings per KLOC

---

## 🎬 How to Demo

### Prerequisites

```bash
# AWS credentials via aws-vault
aws-vault exec driftguard --duration=1h -- aws sts get-caller-identity

# Terraform installed
terraform version

# Conftest installed
conftest --version

# Python 3.11+
python3 --version
```

### Part 1: Bad PR Fails (Policy Gate)

Demonstrate that CI blocks risky Terraform changes before they reach production.

```bash
# Create a new branch with a risky security group
git checkout -b demo/bad-sg

# Edit infra/main.tf to add a wide-open security group
cat >> infra/main.tf << 'EOF'

resource "aws_security_group" "demo_bad" {
  name        = "demo-open-ssh"
  description = "DEMO: intentionally risky SG"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ❌ VIOLATION: C2 control
  }

  tags = var.default_tags
}
EOF

# Generate Terraform plan JSON
cd infra
terraform init
terraform plan -out=plan.bin
terraform show -json plan.bin > plan.json

# Run policy check (should FAIL)
conftest test plan.json -p ../policy --data ../policy/exceptions.yaml

# Expected output:
# FAIL - infra/plan.json - policy.security_groups - deny[msg]
#   Security Group 'demo-open-ssh' allows 0.0.0.0/0 on port 22

# Push to GitHub to trigger CI workflow
cd ..
git add infra/main.tf
git commit -m "demo: add open SSH security group"
git push origin demo/bad-sg

# Open PR on GitHub → CI will FAIL with policy violation
# Screenshot: /docs/pr-fail.png
```

### Part 2: Exception PR Passes with Waiver

Demonstrate time-boxed policy exceptions for legitimate edge cases.

```bash
# Create exception branch
git checkout -b demo/exception-waiver

# Add exception to policy/exceptions.yaml
cat >> policy/exceptions.yaml << 'EOF'

- id: EX-DEMO-001
  owner: SecurityTeam
  reason: Temporary bastion host for vendor audit (expires in 7 days)
  expires: 2030-12-31T23:59:59Z
  resource_id: aws_security_group.demo_bastion
EOF

# Create matching resource with exception ID in name/tags
cat >> infra/main.tf << 'EOF'

resource "aws_security_group" "demo_bastion" {
  name        = "demo-bastion-exception"
  description = "DEMO: waived by EX-DEMO-001"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from internet (EXCEPTION)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.default_tags, {
    Exception = "EX-DEMO-001"
  })
}
EOF

# Run policy check (should PASS with waiver)
cd infra
terraform plan -out=plan.bin
terraform show -json plan.bin > plan.json
conftest test plan.json -p ../policy --data ../policy/exceptions.yaml

# Expected output:
# PASS - policy checks succeeded (exception granted for EX-DEMO-001)

# Push to GitHub
cd ..
git add policy/exceptions.yaml infra/main.tf
git commit -m "demo: add exception for bastion host"
git push origin demo/exception-waiver

# Open PR → CI will PASS with warning about exception
# Screenshot: /docs/exception-waiver.png
```

### Part 3: Manual Drift → Auto-Fix (Lambda)

Demonstrate near real-time auto-remediation of console drift.

**S3 Bucket Drift Simulation**:

```bash
# Deploy DriftGuard infrastructure first
cd infra
aws-vault exec driftguard -- make apply-core

# Create a test S3 bucket manually in AWS Console
# (Or via CLI for automation)
TEST_BUCKET="driftguard-demo-$(date +%s)"

aws s3api create-bucket \
  --bucket "$TEST_BUCKET" \
  --region us-east-1

# Disable Public Access Block (simulate risky action)
aws s3api delete-public-access-block \
  --bucket "$TEST_BUCKET"

# Apply a public bucket policy
cat > /tmp/public-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::${TEST_BUCKET}/*"
  }]
}
EOF

aws s3api put-bucket-policy \
  --bucket "$TEST_BUCKET" \
  --policy file:///tmp/public-policy.json

# ⏱️ WATCH: DriftGuard should remediate in ~30-60 seconds

# Monitor Lambda logs in real-time
aws logs tail /aws/lambda/driftguard-remediator \
  --since 2m --follow

# Expected structured JSON log:
# {"level":"INFO","message":"S3 remediation completed","bucket":"...","actions":["PAB_enabled","policy_sanitized"],"latency_ms":8234}

# Verify remediation
aws s3api get-public-access-block --bucket "$TEST_BUCKET"
# Should show all 4 flags enabled

aws s3api get-bucket-tagging --bucket "$TEST_BUCKET"
# Should include driftguard:remediated=true

# Screenshot: /docs/lambda-logs.png

# Cleanup
aws s3 rb s3://$TEST_BUCKET --force
```

**Security Group Drift Simulation**:

```bash
# Create a test security group with open SSH
VPC_ID=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' \
  --output text)

SG_ID=$(aws ec2 create-security-group \
  --group-name "driftguard-demo-sg-$(date +%s)" \
  --description "DriftGuard drift test" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' \
  --output text)

# Add risky ingress rule (simulate drift)
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# ⏱️ WATCH: DriftGuard should remediate in ~30-60 seconds

# Monitor logs
aws logs tail /aws/lambda/driftguard-remediator \
  --since 2m --follow

# Verify remediation
aws ec2 describe-security-groups --group-ids "$SG_ID"
# Rule 0.0.0.0/0 should be removed
# Maintainer CIDR (/32) should be added

aws ec2 describe-tags \
  --filters "Name=resource-id,Values=$SG_ID"
# Should include driftguard:quarantined=true

# Cleanup
aws ec2 delete-security-group --group-id "$SG_ID"
```

**View Metrics**:

```bash
# Check CloudWatch custom metrics
aws cloudwatch get-metric-statistics \
  --namespace DriftGuard \
  --metric-name RemediationSuccess \
  --dimensions Name=EventType,Value=S3 \
  --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# Generate KPI report
cd ../metrics
python3 collect.py

# View report
cat metrics.md

# Screenshot: /docs/metrics-table.png
```

**Security Hub Findings** (Optional):

```bash
# Check Security Hub for auto-remediation findings
aws securityhub get-findings \
  --filters '{"Title":[{"Value":"DriftGuard","Comparison":"PREFIX"}]}' \
  --query 'Findings[*].[Title,Severity.Label,Compliance.Status]' \
  --output table

# Screenshot: /docs/security-hub-finding.png
```

---

## 📂 Repository Structure

```
driftguard/
├── README.md                        # This file
├── .github/
│   └── workflows/
│       └── security.yml             # CI policy gate (Conftest + Checkov)
├── infra/                           # Terraform infrastructure
│   ├── main.tf                      # Core resources (CloudTrail, EventBridge, Lambda)
│   ├── lambda/
│   │   └── remediator.py            # Auto-remediation playbooks
│   ├── Makefile                     # Build and deploy automation
│   ├── scripts/
│   │   ├── step4_simulate.sh        # Drift simulation helper
│   │   └── step4_cleanup.sh         # Resource cleanup
│   └── README.md                    # Deployment instructions
├── policy/                          # OPA/Rego security policies
│   ├── s3_public_access.rego        # C1: S3 PAB enforcement
│   ├── security_groups.rego         # C2: SG ingress restrictions
│   ├── encryption.rego              # C3: KMS encryption requirements
│   ├── cloudtrail.rego              # C4: CloudTrail baseline
│   ├── iam_policies.rego            # C5: IAM least-privilege
│   ├── exceptions.rego              # Exception handling logic
│   ├── exceptions.yaml              # Time-boxed policy waivers
│   └── README.md                    # Policy testing guide
├── sim/                             # Simulation playbooks
│   ├── PR-cases.md                  # 20+ BAD, 10+ GOOD, 3 EXCEPTION cases
│   └── drift-cases.md               # S3 and SG drift drill procedures
├── metrics/                         # KPI collection and reporting
│   ├── collect.py                   # Metrics aggregation tool
│   ├── input/                       # Sample/real input data
│   ├── metrics.md                   # Generated KPI report
│   └── README.md                    # Usage instructions
└── docs/                            # Screenshots and diagrams
    ├── pr-fail.png                  # CI blocking bad PR
    ├── exception-waiver.png         # Exception granted
    ├── lambda-logs.png              # Structured JSON logs
    ├── metrics-table.png            # KPI dashboard
    └── security-hub-finding.png     # Security Hub integration
```

---

## ⚠️ Safety and Cost Considerations

### Sandbox-Only Deployment

**WARNING**: DriftGuard is designed for **non-production sandbox accounts** during initial deployment and testing.

- Lambda has **write permissions** to modify S3 buckets and security groups automatically
- Auto-remediation can cause service disruptions if misconfigured
- Test thoroughly in an isolated AWS account before considering production use

### Budget Cautions

Estimated monthly costs for a low-traffic deployment (us-east-1):

| Service | Usage | Cost |
|---------|-------|------|
| CloudTrail | Management events only (first trail free) | $0 |
| Lambda | ~100 invocations/month @ 256MB, 10s avg | ~$0.01 |
| CloudWatch Logs | ~1GB ingestion + 30-day retention | ~$0.50 |
| EventBridge | ~100 events/month | $0.00 |
| GuardDuty | Continuous threat detection | ~$4.50/month |
| Security Hub | 10,000 checks/month (first 10k free) | $0 |
| **Total** | | **~$5/month** |

**To minimize costs**:
- Use CloudWatch Logs retention policies (default: 30 days)
- Consider disabling GuardDuty and Security Hub in test environments
- Delete S3 test buckets and security groups after each drill

### Cleanup and Rollback

**Before destroying infrastructure**:

```bash
# List all resources created by DriftGuard
cd infra
terraform state list

# Remove any test resources first
aws s3 ls | grep driftguard-demo
aws ec2 describe-security-groups \
  --filters Name=tag:Project,Values=driftguard

# Destroy DriftGuard infrastructure
aws-vault exec driftguard -- terraform destroy

# Verify cleanup
aws cloudtrail describe-trails
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/driftguard
aws events list-rules --name-prefix driftguard
```

**To disable auto-remediation temporarily without destroying**:

```bash
# Disable EventBridge rule
aws events disable-rule --name driftguard-remediation-trigger

# Re-enable when ready
aws events enable-rule --name driftguard-remediation-trigger
```

---

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/AmirithaGuru/driftguard.git
cd driftguard

# Configure AWS credentials
aws-vault add driftguard
aws-vault exec driftguard -- aws sts get-caller-identity
```

### 2. Deploy Infrastructure

```bash
cd infra

# Package Lambda function
make lambda-package

# Deploy core infrastructure
aws-vault exec driftguard -- make apply-core

# Verify deployment
aws lambda get-function --function-name driftguard-remediator
aws events list-rules --name-prefix driftguard
```

### 3. Test Policy Gates

```bash
# Generate and validate a Terraform plan
terraform plan -out=plan.bin
terraform show -json plan.bin > plan.json

# Run policy checks
make policy-check

# Expected: PASS (no violations in base infrastructure)
```

### 4. Simulate Drift

```bash
# Run automated drift simulation
./scripts/step4_simulate.sh --region us-east-1 --prefix dg-demo

# Monitor Lambda logs
aws logs tail /aws/lambda/driftguard-remediator --follow

# Cleanup test resources
./scripts/step4_cleanup.sh --bucket <test-bucket-name> --sg-id <test-sg-id>
```

### 5. Generate Metrics

```bash
cd ../metrics

# Create sample data (first run)
python3 collect.py --init-samples

# Generate report
python3 collect.py

# View KPIs
cat metrics.md
```

---

## 📚 Further Reading

- **Policy Development**: See `policy/README.md` for writing custom Rego rules and testing
- **Simulation Playbooks**: See `sim/PR-cases.md` and `sim/drift-cases.md` for comprehensive test scenarios
- **Metrics Collection**: See `metrics/README.md` for KPI definitions and data sources
- **Lambda Internals**: See `infra/lambda/remediator.py` for playbook implementation details
- **CI/CD Integration**: See `.github/workflows/security.yml` for GitHub Actions configuration

---

## 🤝 Contributing

DriftGuard is a reference implementation for guardrails-as-code patterns. Contributions welcome:

1. **New Policies**: Add Rego rules for additional AWS services (RDS encryption, VPC flow logs, etc.)
2. **New Playbooks**: Extend Lambda remediator for EBS, RDS, IAM drift scenarios
3. **Enhanced Metrics**: Add support for Prometheus/Grafana exports
4. **Documentation**: Add screenshots, architecture diagrams, or video walkthroughs

---

## 📄 License

MIT License - see LICENSE file for details.

---

## 🙏 Acknowledgments

Built with:
- **Terraform** for infrastructure as code
- **OPA/Conftest** for policy-as-code enforcement  
- **Checkov** for static IaC security scanning
- **AWS CloudTrail** for management event detection
- **AWS EventBridge** for event routing
- **AWS Lambda** for serverless remediation
- **Python 3.11** and **Boto3** for AWS SDK integration

Inspired by AWS Well-Architected Security Pillar and DevSecOps best practices.

---

**Built with ❤️ for secure, automated AWS infrastructure management.**