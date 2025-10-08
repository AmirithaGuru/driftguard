#!/bin/bash

# DriftGuard Step 4: Simulate risky drift for manual testing
# Creates public S3 bucket and open security group to trigger auto-remediation

set -e

# Default values
REGION=${AWS_DEFAULT_REGION:-us-east-1}
PREFIX="dg-demo"
SUFFIX=$(date +%s)

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --region)
      REGION="$2"
      shift 2
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

echo "🚨 DriftGuard Step 4: Simulating Risky Drift"
echo "Region: $REGION"
echo "Prefix: $PREFIX"
echo ""

# 1. Create public S3 bucket
BUCKET_NAME="${PREFIX}-public-bucket-${SUFFIX}"
echo "📦 Creating public S3 bucket: $BUCKET_NAME"

aws s3api create-bucket --bucket "$BUCKET_NAME" --region "$REGION" --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket --bucket "$BUCKET_NAME" --region "$REGION"

# Apply public bucket policy
aws s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::'"$BUCKET_NAME"'/*"
    }
  ]
}'

echo "✅ S3 bucket $BUCKET_NAME created with public policy"

# 2. Create security group with open SSH
echo ""
echo "🔒 Creating security group with open SSH access..."

# Get default VPC
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output text --region "$REGION")

# Create security group
SG_NAME="${PREFIX}-open-ssh-${SUFFIX}"
SG_ID=$(aws ec2 create-security-group \
  --group-name "$SG_NAME" \
  --description "Test SG with open SSH for DriftGuard testing" \
  --vpc-id "$VPC_ID" \
  --region "$REGION" \
  --query "GroupId" --output text)

# Add dangerous ingress rule
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr "0.0.0.0/0" \
  --region "$REGION"

echo "✅ Security group $SG_ID created with 0.0.0.0/0:22"

# 3. Wait for auto-remediation
echo ""
echo "⏳ Waiting 60 seconds for auto-remediation to trigger..."
sleep 60

# 4. Check results
echo ""
echo "🔍 Checking auto-remediation results..."

# Check S3 bucket policy
echo "S3 Bucket Policy Status:"
aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null || echo "❌ No policy found (remediated!)"

# Check security group rules
echo ""
echo "Security Group Rules:"
aws ec2 describe-security-groups --group-ids "$SG_ID" --region "$REGION" --query "SecurityGroups[0].IpPermissions" --output table

echo ""
echo "📊 Check CloudWatch Logs:"
echo "aws logs filter-log-events --log-group-name /aws/lambda/driftguard-remediator-* --start-time \$(date -d '5 minutes ago' +%s)000"

echo ""
echo "📈 Check CloudWatch Metrics:"
echo "aws cloudwatch get-metric-statistics --namespace DriftGuard --metric-name RemediationSuccess --start-time \$(date -d '10 minutes ago' -u +%Y-%m-%dT%H:%M:%S) --end-time \$(date -u +%Y-%m-%dT%H:%M:%S) --period 300 --statistics Sum"

echo ""
echo "🧹 Cleanup commands:"
echo "./step4_cleanup.sh --bucket $BUCKET_NAME --sg-id $SG_ID --region $REGION"
