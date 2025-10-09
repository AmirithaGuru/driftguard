# DriftGuard Drift Simulation Drills

## Purpose

This document provides hands-on drift simulation scenarios to measure DriftGuard's auto-remediation
performance. These drills help validate detection latency, invoke latency, remediation latency, and
end-to-end MTTR (Mean Time To Remediation).

## Safety Notice

**IMPORTANT**: Use TEST buckets and security groups only. Never run these drills against production
resources. Always clean up test resources after verification.

---

## S3 Drift Drills

### S3 Drift Drill 1: Public Access via ACL

#### Prerequisites

- DriftGuard Step 4 deployed and operational
- AWS CLI configured with appropriate permissions
- CloudWatch Logs access

#### Step Checklist

- Create test S3 bucket with unique name
- Verify bucket is initially private
- Make bucket public via ACL (t0)
- Monitor CloudWatch logs for EventBridge trigger (t1)
- Watch Lambda execution logs (t2)
- Confirm remediation completion (t3)
- Verify bucket is secured
- Clean up test resources

#### Execution Steps

#### Step 1: Create test bucket

```bash
# Create unique bucket name
BUCKET_NAME="driftguard-test-$(date +%s)-$(whoami)"

# Create bucket
aws s3api create-bucket --bucket $BUCKET_NAME --region us-east-1

# Verify initial state (should be private)
aws s3api get-bucket-acl --bucket $BUCKET_NAME
```

#### Step 2: Make public via ACL (t0)

```bash
# Set public ACL - THIS IS THE DRIFT EVENT (t0)
aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl public-read

# Note the exact timestamp when you execute this command
echo "t0 (drift): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
```

#### Step 3: Monitor for detection (t1)

```bash
# Watch CloudWatch logs for EventBridge trigger
aws logs tail /aws/lambda/driftguard-remediator-8cb448d0 --since 5m --follow

# Look for: "Processing CloudTrail event" with event_name "PutBucketAcl"
# Note timestamp when this appears (t1)
```

#### Step 4: Monitor lambda execution (t2-t3)

```bash
# Continue watching logs for:
# t2: First playbook log entry (e.g., "S3 remediation started")
# t3: Success/failure log entry (e.g., "S3 remediation completed")
```

#### Timestamp Recording Table

| Metric                     | Timestamp | Value   |
| -------------------------- | --------- | ------- |
| t0 (Drift)                 |           |         |
| t1 (EventBridge Detection) |           |         |
| t2 (Lambda Start)          |           |         |
| t3 (Lambda End)            |           |         |
| **Detection Latency**      |           | t1 - t0 |
| **Invoke Latency**         |           | t2 - t1 |
| **Remediation Latency**    |           | t3 - t2 |
| **MTTR**                   |           | t3 - t0 |

#### Verification Checklist

- Public ACL removed or bucket made private
- Public Access Block enabled on bucket
- Bucket tagged with `driftguard:remediated=true`
- No public access possible

**Verification Commands:**

```bash
# Check ACL (should be private)
aws s3api get-bucket-acl --bucket $BUCKET_NAME

# Check Public Access Block (should be enabled)
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Check tags
aws s3api get-bucket-tagging --bucket $BUCKET_NAME

# Test public access (should fail)
curl -I "https://$BUCKET_NAME.s3.amazonaws.com/"
```

#### Rollback Steps

```bash
# If remediation failed, manually secure the bucket
aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private

# Enable Public Access Block
aws s3api put-public-access-block --bucket $BUCKET_NAME \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Clean up test bucket
aws s3api delete-bucket --bucket $BUCKET_NAME
```

---

### S3 Drift Drill 2: Public Access via Bucket Policy

#### Step Checklist

- Create test S3 bucket with unique name
- Disable Public Access Block (required for policy)
- Apply public bucket policy (t0)
- Monitor CloudWatch logs for EventBridge trigger (t1)
- Watch Lambda execution logs (t2)
- Confirm remediation completion (t3)
- Verify bucket is secured
- Clean up test resources

#### Execution Steps

#### Step 1: Create test bucket and disable PAB

```bash
# Create unique bucket name
BUCKET_NAME="driftguard-test-policy-$(date +%s)-$(whoami)"

# Create bucket
aws s3api create-bucket --bucket $BUCKET_NAME --region us-east-1

# Disable Public Access Block (required for bucket policy)
aws s3api put-public-access-block --bucket $BUCKET_NAME \
  --public-access-block-configuration \
  "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
```

#### Step 2: Apply public bucket policy (t0)

```bash
# Create public bucket policy - THIS IS THE DRIFT EVENT (t0)
cat > public-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
    }
  ]
}
EOF

# Apply the policy
aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy file://public-policy.json

# Note the exact timestamp when you execute this command
echo "t0 (drift): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
```

#### Step 3: Monitor for detection (t1)

```bash
# Watch CloudWatch logs for EventBridge trigger
aws logs tail /aws/lambda/driftguard-remediator-8cb448d0 --since 5m --follow

# Look for: "Processing CloudTrail event" with event_name "PutBucketPolicy"
# Note timestamp when this appears (t1)
```

#### Step 4: Monitor lambda execution (t2-t3)

```bash
# Continue watching logs for:
# t2: First S3 remediation log entry
# t3: S3 remediation completion log entry
```

#### Timestamp Recording Table

| Metric                     | Timestamp | Value   |
| -------------------------- | --------- | ------- |
| t0 (Drift)                 |           |         |
| t1 (EventBridge Detection) |           |         |
| t2 (Lambda Start)          |           |         |
| t3 (Lambda End)            |           |         |
| **Detection Latency**      |           | t1 - t0 |
| **Invoke Latency**         |           | t2 - t1 |
| **Remediation Latency**    |           | t3 - t2 |
| **MTTR**                   |           | t3 - t0 |

#### Verification Checklist

- Public bucket policy removed
- Public Access Block re-enabled on bucket
- Bucket tagged with `driftguard:remediated=true`
- No public access possible

**Verification Commands:**

```bash
# Check bucket policy (should be removed or not public)
aws s3api get-bucket-policy --bucket $BUCKET_NAME 2>/dev/null || echo "No policy found (good)"

# Check Public Access Block (should be enabled)
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Check tags
aws s3api get-bucket-tagging --bucket $BUCKET_NAME

# Test public access (should fail)
curl -I "https://$BUCKET_NAME.s3.amazonaws.com/"
```

#### Rollback Steps

```bash
# If remediation failed, manually secure the bucket
aws s3api delete-bucket-policy --bucket $BUCKET_NAME

# Enable Public Access Block
aws s3api put-public-access-block --bucket $BUCKET_NAME \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Clean up test bucket
aws s3api delete-bucket --bucket $BUCKET_NAME
```

---

## Security Group Drift Drills

### Security Group Drift Drill 1: Open SSH Access (IPv4)

#### Step Checklist

- Create test security group in default VPC
- Add dangerous ingress rule (0.0.0.0/0:22) (t0)
- Monitor CloudWatch logs for EventBridge trigger (t1)
- Watch Lambda execution logs (t2)
- Confirm remediation completion (t3)
- Verify security group is secured
- Clean up test resources

#### Execution Steps

#### Step 1: Create test security group

```bash
# Get default VPC ID
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output text)

# Create test security group
SG_ID=$(aws ec2 create-security-group \
  --group-name "driftguard-test-sg-$(date +%s)" \
  --description "Test SG for DriftGuard drift simulation" \
  --vpc-id $VPC_ID \
  --query "GroupId" --output text)

echo "Created security group: $SG_ID"
```

#### Step 2: Add dangerous ingress rule (t0)

```bash
# Add dangerous SSH rule - THIS IS THE DRIFT EVENT (t0)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr "0.0.0.0/0"

# Note the exact timestamp when you execute this command
echo "t0 (drift): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
```

#### Step 3: Monitor for detection (t1)

```bash
# Watch CloudWatch logs for EventBridge trigger
aws logs tail /aws/lambda/driftguard-remediator-8cb448d0 --since 5m --follow

# Look for: "Processing CloudTrail event" with event_name "AuthorizeSecurityGroupIngress"
# Note timestamp when this appears (t1)
```

#### Step 4: Monitor lambda execution (t2-t3)

```bash
# Continue watching logs for:
# t2: First security group remediation log entry
# t3: Security group remediation completion log entry
```

#### Timestamp Recording Table

| Metric                     | Timestamp | Value   |
| -------------------------- | --------- | ------- |
| t0 (Drift)                 |           |         |
| t1 (EventBridge Detection) |           |         |
| t2 (Lambda Start)          |           |         |
| t3 (Lambda End)            |           |         |
| **Detection Latency**      |           | t1 - t0 |
| **Invoke Latency**         |           | t2 - t1 |
| **Remediation Latency**    |           | t3 - t2 |
| **MTTR**                   |           | t3 - t0 |

#### Verification Checklist

- Dangerous 0.0.0.0/0:22 rule removed
- Maintainer access (203.0.113.10/32:22) added
- Maintainer access (203.0.113.10/32:3389) added
- Security group tagged with `driftguard:quarantined=true`

**Verification Commands:**

```bash
# Check security group rules
aws ec2 describe-security-groups --group-ids $SG_ID --query "SecurityGroups[0].IpPermissions"

# Check tags
aws ec2 describe-tags --filters "Name=resource-id,Values=$SG_ID"

# Verify no 0.0.0.0/0 rules exist
aws ec2 describe-security-groups --group-ids $SG_ID \
  --query "SecurityGroups[0].IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0')]"
```

#### Rollback Steps

```bash
# If remediation failed, manually secure the security group
# Remove dangerous rules
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr "0.0.0.0/0"

# Add maintainer access
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr "203.0.113.10/32"

aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 3389 \
  --cidr "203.0.113.10/32"

# Tag as quarantined
aws ec2 create-tags \
  --resources $SG_ID \
  --tags Key=driftguard:quarantined,Value=true

# Clean up test security group
aws ec2 delete-security-group --group-id $SG_ID
```

---

### Security Group Drift Drill 2: Open SSH Access (IPv6)

#### Step Checklist

- Create test security group in default VPC
- Add dangerous IPv6 ingress rule (::/0:22) (t0)
- Monitor CloudWatch logs for EventBridge trigger (t1)
- Watch Lambda execution logs (t2)
- Confirm remediation completion (t3)
- Verify security group is secured
- Clean up test resources

#### Execution Steps

#### Step 1: Create test security group

```bash
# Get default VPC ID
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output text)

# Create test security group
SG_ID=$(aws ec2 create-security-group \
  --group-name "driftguard-test-sg-ipv6-$(date +%s)" \
  --description "Test SG for DriftGuard IPv6 drift simulation" \
  --vpc-id $VPC_ID \
  --query "GroupId" --output text)

echo "Created security group: $SG_ID"
```

#### Step 2: Add dangerous IPv6 ingress rule (t0)

```bash
# Add dangerous IPv6 SSH rule - THIS IS THE DRIFT EVENT (t0)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --ipv6-cidr-blocks "::/0"

# Note the exact timestamp when you execute this command
echo "t0 (drift): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
```

**Step 3-4: Monitor Detection and Execution**

```bash
# Same monitoring steps as IPv4 drill
# Look for same log patterns
```

#### Timestamp Recording Table

| Metric                     | Timestamp | Value   |
| -------------------------- | --------- | ------- |
| t0 (Drift)                 |           |         |
| t1 (EventBridge Detection) |           |         |
| t2 (Lambda Start)          |           |         |
| t3 (Lambda End)            |           |         |
| **Detection Latency**      |           | t1 - t0 |
| **Invoke Latency**         |           | t2 - t1 |
| **Remediation Latency**    |           | t3 - t2 |
| **MTTR**                   |           | t3 - t0 |

#### Verification and Rollback

Same verification and rollback steps as IPv4 drill, but check for IPv6 rules:

```bash
# Check for IPv6 rules
aws ec2 describe-security-groups --group-ids $SG_ID \
  --query "SecurityGroups[0].IpPermissions[?Ipv6Ranges]"

# Remove IPv6 dangerous rules
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --ipv6-cidr-blocks "::/0"
```

---

## Timestamp Capture Guide

### How to Capture Accurate Timestamps

#### t0: Drift Event

- **When**: The exact moment you execute the drift command
- **Method**: Use `date` command immediately before/after the drift action
- **Command**: `echo "t0 (drift): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"`

#### t1: EventBridge Detection

- **When**: First CloudWatch log entry from Lambda handler
- **Look for**: `"Processing CloudTrail event"` with matching `event_name`
- **Method**: Monitor logs with timestamp precision
- **Command**: `aws logs tail /aws/lambda/driftguard-remediator-8cb448d0 --since 15m --follow`

#### t2: Lambda Execution Start

- **When**: First playbook-specific log entry
- **Look for**: `"S3 remediation started"` or `"Security group remediation started"`
- **Method**: Parse structured JSON logs for remediation start

#### t3: Lambda Execution End

- **When**: Final success/failure log entry
- **Look for**: `"remediation completed"` or `"remediation failed"`
- **Method**: Parse structured JSON logs for completion

### CLI Commands for Log Monitoring

```bash
# Real-time log monitoring
aws logs tail /aws/lambda/driftguard-remediator-8cb448d0 --since 15m --follow

# Filter for specific events
aws logs filter-log-events \
  --log-group-name /aws/lambda/driftguard-remediator-8cb448d0 \
  --start-time $(date -d '15 minutes ago' +%s)000 \
  --filter-pattern "Processing CloudTrail event"

# Get recent logs with timestamps
aws logs filter-log-events \
  --log-group-name /aws/lambda/driftguard-remediator-8cb448d0 \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --query "events[].{timestamp:timestamp,message:message}"
```

---

## CloudWatch Metrics Analysis

### Custom Metrics Location

- **Namespace**: `DriftGuard`
- **Metrics**:
  - `RemediationSuccess` (Count)
  - `RemediationFailure` (Count)
  - `RemediationLatencyMs` (Milliseconds)

### Metrics Queries

#### View Recent Remediation Success Rate

```bash
aws cloudwatch get-metric-statistics \
  --namespace DriftGuard \
  --metric-name RemediationSuccess \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### View Remediation Latency

```bash
aws cloudwatch get-metric-statistics \
  --namespace DriftGuard \
  --metric-name RemediationLatencyMs \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average,Maximum
```

### CloudWatch Console Navigation

1. Go to CloudWatch → Metrics → Custom Namespaces
2. Select `DriftGuard` namespace
3. Choose metric to visualize:
   - **RemediationSuccess**: Graph as line chart (Sum over time)
   - **RemediationFailure**: Graph as line chart (Sum over time)
   - **RemediationLatencyMs**: Graph as line chart (Average, p50, p95)

---

## Metrics Cookbook

### Per-Case Metrics Calculation

#### Detection Latency (p50/p95)

```bash
# Collect multiple drill results and calculate percentiles
# Example: Detection latencies from 5 drills
# [1.2s, 1.8s, 1.5s, 2.1s, 1.3s]
# p50 = 1.5s, p95 = 2.1s
```

#### MTTR (Mean Time To Remediation)

```bash
# MTTR = (t3 - t0) for each drill
# Average MTTR = sum(all_MTTRs) / number_of_drills
```

#### Success Rate

```bash
# Success Rate = (Successful Remediations / Total Drills) * 100
# Example: 8 successful out of 10 drills = 80% success rate
```

### Weekly Roll-up Metrics

| Metric                      | Week 1 | Week 2 | Week 3 | Week 4 | Target |
| --------------------------- | ------ | ------ | ------ | ------ | ------ |
| **Detection Latency p50**   |        |        |        |        | < 2s   |
| **Detection Latency p95**   |        |        |        |        | < 5s   |
| **Invoke Latency p50**      |        |        |        |        | < 1s   |
| **Invoke Latency p95**      |        |        |        |        | < 2s   |
| **Remediation Latency p50** |        |        |        |        | < 30s  |
| **Remediation Latency p95** |        |        |        |        | < 60s  |
| **MTTR p50**                |        |        |        |        | < 35s  |
| **MTTR p95**                |        |        |        |        | < 65s  |
| **Success Rate**            |        |        |        |        | > 95%  |
| **Drills Conducted**        |        |        |        |        |        |

### Weekly Summary Template

**Week of**: [Date Range]  
**Total Drills Conducted**: [Number]  
**S3 ACL Drills**: [Number]  
**S3 Policy Drills**: [Number]  
**SG IPv4 Drills**: [Number]  
**SG IPv6 Drills**: [Number]

**Performance Metrics**:

- Detection Latency p50: [Value]s (Target: <2s)
- Detection Latency p95: [Value]s (Target: <5s)
- MTTR p50: [Value]s (Target: <35s)
- MTTR p95: [Value]s (Target: <65s)
- Success Rate: [Percentage]% (Target: >95%)

**Issues Found**:

- [List any remediation failures]
- [List any false positives/negatives]
- [List any performance degradation]

**Improvements Needed**:

- [Lambda function optimizations]
- [EventBridge rule tuning]
- [Policy rule adjustments]

---

## Safety and Cleanup

### Pre-Drill Safety Checklist

- Confirm you're in the correct AWS account
- Verify no production resources will be affected
- Use unique naming for test resources
- Have rollback procedures ready
- Document all test resource names

### Post-Drill Cleanup Checklist

- Delete all test S3 buckets
- Delete all test security groups
- Verify no test resources remain
- Check for any orphaned resources
- Confirm account is clean

### Emergency Rollback Procedures

#### If Lambda Fails to Remediate

```bash
# For S3 buckets
aws s3api put-bucket-acl --bucket [BUCKET_NAME] --acl private
aws s3api put-public-access-block --bucket [BUCKET_NAME] \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# For security groups
aws ec2 revoke-security-group-ingress --group-id [SG_ID] \
  --protocol tcp --port 22 --cidr "0.0.0.0/0"
aws ec2 authorize-security-group-ingress --group-id [SG_ID] \
  --protocol tcp --port 22 --cidr "203.0.113.10/32"
```

#### If DriftGuard is Down

1. Disable EventBridge rule temporarily
2. Manually remediate any open resources
3. Re-enable EventBridge rule
4. Investigate Lambda function issues

### Verification Commands

```bash
# Verify no public S3 buckets
aws s3api list-buckets --query "Buckets[].Name" | xargs -I {} sh -c 'aws s3api get-public-access-block --bucket {} 2>/dev/null || echo "{}: No PAB"'

# Verify no open security groups
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0')]].GroupId"

# Check for driftguard tags
aws resourcegroupstaggingapi get-resources --tag-filters Key=driftguard:remediated,Values=true
aws resourcegroupstaggingapi get-resources --tag-filters Key=driftguard:quarantined,Values=true
```

---

## Commit & Push

```bash
git add .
git commit -m "docs(sim): PR and drift scenarios"
git push
```
