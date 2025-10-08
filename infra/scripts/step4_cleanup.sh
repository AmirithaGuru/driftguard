#!/bin/bash

# DriftGuard Step 4: Cleanup test resources
# Removes S3 bucket and security group created by step4_simulate.sh

set -e

# Default values
REGION=${AWS_DEFAULT_REGION:-us-east-1}
BUCKET_NAME=""
SG_ID=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --bucket)
      BUCKET_NAME="$2"
      shift 2
      ;;
    --sg-id)
      SG_ID="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

echo "🧹 DriftGuard Step 4: Cleaning up test resources"
echo "Region: $REGION"
echo ""

if [[ -n "$BUCKET_NAME" ]]; then
  echo "🗑️  Cleaning up S3 bucket: $BUCKET_NAME"
  
  # Remove bucket policy
  aws s3api delete-bucket-policy --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null || echo "No bucket policy to remove"
  
  # Remove all objects and delete bucket
  aws s3 rm "s3://$BUCKET_NAME" --recursive --region "$REGION" 2>/dev/null || echo "Bucket already empty"
  aws s3api delete-bucket --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null || echo "Bucket already deleted"
  
  echo "✅ S3 bucket $BUCKET_NAME cleaned up"
fi

if [[ -n "$SG_ID" ]]; then
  echo ""
  echo "🗑️  Cleaning up security group: $SG_ID"
  
  # Delete security group
  aws ec2 delete-security-group --group-id "$SG_ID" --region "$REGION" 2>/dev/null || echo "Security group already deleted"
  
  echo "✅ Security group $SG_ID cleaned up"
fi

echo ""
echo "✅ Cleanup complete!"
