#!/usr/bin/env python3
"""
DriftGuard Auto-Remediation Lambda Function

This Lambda function automatically remediates risky AWS configurations detected via CloudTrail events:
- S3 buckets: Enforces Public Access Block and sanitizes policies
- Security Groups: Removes dangerous 0.0.0.0/0 rules and adds maintainer access

Author: DriftGuard Team
Runtime: Python 3.11
"""

import json
import os
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, Optional, List

# Configure boto3 clients with retry configuration
config = Config(
    retries={
        'max_attempts': 3,
        'mode': 'adaptive'
    }
)

# Initialize AWS clients
s3_client = boto3.client('s3', config=config)
s3control_client = boto3.client('s3control', config=config)
ec2_client = boto3.client('ec2', config=config)
cloudwatch_client = boto3.client('cloudwatch', config=config)
securityhub_client = boto3.client('securityhub', config=config)

# Environment variables
PROJECT = os.environ.get('PROJECT', 'driftguard')
METRIC_NAMESPACE = os.environ.get('METRIC_NAMESPACE', 'DriftGuard')
MAINTAINER_CIDR = os.environ.get('MAINTAINER_CIDR', '203.0.113.10/32')
ENABLE_SECURITY_HUB = os.environ.get('ENABLE_SECURITY_HUB', 'false').lower() == 'true'


def json_logger(level: str, message: str, **kwargs) -> None:
    """
    Structured JSON logging for CloudWatch Logs.
    Single-line JSON format for better searchability and parsing.
    """
    log_entry = {
        'timestamp': time.time(),
        'level': level,
        'message': message,
        'project': PROJECT,
        **kwargs
    }
    print(json.dumps(log_entry))


def put_metric(metric_name: str, value: float, unit: str = 'Count') -> None:
    """
    Send custom CloudWatch metric for monitoring remediation actions.
    """
    try:
        cloudwatch_client.put_metric_data(
            Namespace=METRIC_NAMESPACE,
            MetricData=[
                {
                    'MetricName': metric_name,
                    'Value': value,
                    'Unit': unit,
                    'Dimensions': [
                        {
                            'Name': 'Project',
                            'Value': PROJECT
                        }
                    ]
                }
            ]
        )
    except Exception as e:
        json_logger('ERROR', f'Failed to put metric {metric_name}', error=str(e))


def publish_security_hub_finding(resource_type: str, resource_id: str, 
                                remediation_action: str) -> None:
    """
    Publish a Security Hub finding for the remediation action.
    Optional feature - only runs if ENABLE_SECURITY_HUB is true.
    """
    if not ENABLE_SECURITY_HUB:
        return
        
    try:
        finding = {
            'SchemaVersion': '2018-10-08',
            'Id': f'{PROJECT}-remediation-{resource_type}-{resource_id}',
            'ProductArn': f'arn:aws:securityhub:{os.environ.get("AWS_REGION", "us-east-1")}:{os.environ.get("AWS_ACCOUNT_ID", "123456789012")}:product/{PROJECT}/driftguard',
            'GeneratorId': f'{PROJECT}-remediator',
            'AwsAccountId': os.environ.get('AWS_ACCOUNT_ID', '123456789012'),
            'Types': ['Software and Configuration Checks/AWS Config Analysis'],
            'CreatedAt': time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime()),
            'UpdatedAt': time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime()),
            'Severity': {
                'Label': 'INFORMATIONAL'
            },
            'Title': 'Auto-remediated by DriftGuard',
            'Description': f'DriftGuard automatically remediated {resource_type} {resource_id}: {remediation_action}',
            'Remediation': {
                'Recommendation': {
                    'Text': f'DriftGuard automatically applied remediation: {remediation_action}'
                }
            },
            'Resources': [
                {
                    'Type': resource_type,
                    'Id': resource_id,
                    'Region': os.environ.get('AWS_REGION', 'us-east-1')
                }
            ]
        }
        
        securityhub_client.batch_import_findings(
            Findings=[finding]
        )
        json_logger('INFO', 'Security Hub finding published', 
                   resource_type=resource_type, resource_id=resource_id)
    except Exception as e:
        json_logger('WARN', 'Failed to publish Security Hub finding', 
                   error=str(e), resource_type=resource_type, resource_id=resource_id)


def set_public_access_block(bucket: str) -> bool:
    """
    Enforce all four Public Access Block flags on an S3 bucket.
    Uses S3Control API for account-level Public Access Block management.
    """
    try:
        s3control_client.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        json_logger('INFO', 'Public Access Block enforced', bucket=bucket)
        return True
    except ClientError as e:
        json_logger('ERROR', 'Failed to set Public Access Block', 
                   bucket=bucket, error=str(e))
        return False


def sanitize_bucket_policy(bucket: str) -> bool:
    """
    Remove public ('*') statements from bucket policy that allow broad access.
    Keeps legitimate statements for CloudTrail, ELB, etc.
    """
    try:
        # Get current bucket policy
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket)
            policy = json.loads(policy_response['Policy'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                json_logger('INFO', 'No bucket policy to sanitize', bucket=bucket)
                return True
            raise
        
        # Filter out public statements
        original_statements = policy.get('Statement', [])
        sanitized_statements = []
        
        for statement in original_statements:
            # Keep statements that don't grant public access
            if (statement.get('Principal') != '*' and 
                statement.get('Principal') != {'AWS': '*'}):
                sanitized_statements.append(statement)
            else:
                json_logger('INFO', 'Removed public statement from bucket policy', 
                           bucket=bucket, statement_id=statement.get('Sid', 'Unknown'))
        
        # Update policy if changes were made
        if len(sanitized_statements) != len(original_statements):
            if sanitized_statements:
                policy['Statement'] = sanitized_statements
                s3_client.put_bucket_policy(
                    Bucket=bucket,
                    Policy=json.dumps(policy)
                )
                json_logger('INFO', 'Bucket policy sanitized', 
                           bucket=bucket, 
                           removed_count=len(original_statements) - len(sanitized_statements))
            else:
                # Remove empty policy
                s3_client.delete_bucket_policy(Bucket=bucket)
                json_logger('INFO', 'Bucket policy removed (was all public)', bucket=bucket)
        
        return True
    except Exception as e:
        json_logger('ERROR', 'Failed to sanitize bucket policy', 
                   bucket=bucket, error=str(e))
        return False


def tag_bucket(bucket: str, key: str, value: str) -> bool:
    """
    Tag an S3 bucket with remediation metadata.
    """
    try:
        s3_client.put_bucket_tagging(
            Bucket=bucket,
            Tagging={
                'TagSet': [
                    {'Key': key, 'Value': value}
                ]
            }
        )
        json_logger('INFO', 'Bucket tagged', bucket=bucket, key=key, value=value)
        return True
    except Exception as e:
        json_logger('ERROR', 'Failed to tag bucket', 
                   bucket=bucket, error=str(e))
        return False


def describe_security_group(group_id: str) -> Optional[Dict[str, Any]]:
    """
    Describe a security group and return its configuration.
    """
    try:
        response = ec2_client.describe_security_groups(
            GroupIds=[group_id]
        )
        return response['SecurityGroups'][0] if response['SecurityGroups'] else None
    except Exception as e:
        json_logger('ERROR', 'Failed to describe security group', 
                   group_id=group_id, error=str(e))
        return None


def revoke_dangerous_ingress(group_id: str, security_group: Dict[str, Any]) -> int:
    """
    Revoke dangerous ingress rules (0.0.0.0/0 on ports 22/3389 or protocol all).
    Returns number of rules revoked.
    """
    dangerous_rules = []
    
    for rule in security_group.get('IpPermissions', []):
        # Check for dangerous rules
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                # Check if it's on dangerous ports or all protocols
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                protocol = rule.get('IpProtocol')
                
                is_dangerous = (
                    (from_port == 22 and to_port == 22) or  # SSH
                    (from_port == 3389 and to_port == 3389) or  # RDP
                    protocol == '-1' or  # All protocols
                    (from_port == 0 and to_port == 65535)  # All ports
                )
                
                if is_dangerous:
                    dangerous_rules.append(rule)
                    json_logger('INFO', 'Found dangerous ingress rule', 
                               group_id=group_id, protocol=protocol, 
                               from_port=from_port, to_port=to_port)
    
    # Revoke dangerous rules
    revoked_count = 0
    for rule in dangerous_rules:
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[rule]
            )
            revoked_count += 1
            json_logger('INFO', 'Revoked dangerous ingress rule', 
                       group_id=group_id, rule=rule)
        except Exception as e:
            json_logger('ERROR', 'Failed to revoke dangerous rule', 
                       group_id=group_id, error=str(e))
    
    return revoked_count


def authorize_maintainer_access(group_id: str) -> bool:
    """
    Add maintainer CIDR access for SSH (22) and RDP (3389) ports.
    """
    try:
        maintainer_rules = []
        
        # SSH access
        maintainer_rules.append({
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': MAINTAINER_CIDR}]
        })
        
        # RDP access
        maintainer_rules.append({
            'IpProtocol': 'tcp',
            'FromPort': 3389,
            'ToPort': 3389,
            'IpRanges': [{'CidrIp': MAINTAINER_CIDR}]
        })
        
        ec2_client.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=maintainer_rules
        )
        
        json_logger('INFO', 'Added maintainer access', 
                   group_id=group_id, maintainer_cidr=MAINTAINER_CIDR)
        return True
    except Exception as e:
        json_logger('ERROR', 'Failed to add maintainer access', 
                   group_id=group_id, error=str(e))
        return False


def tag_security_group(group_id: str, key: str, value: str) -> bool:
    """
    Tag a security group with remediation metadata.
    """
    try:
        ec2_client.create_tags(
            Resources=[group_id],
            Tags=[{'Key': key, 'Value': value}]
        )
        json_logger('INFO', 'Security group tagged', 
                   group_id=group_id, key=key, value=value)
        return True
    except Exception as e:
        json_logger('ERROR', 'Failed to tag security group', 
                   group_id=group_id, error=str(e))
        return False


def extract_bucket_name(event_detail: Dict[str, Any]) -> Optional[str]:
    """
    Extract bucket name from CloudTrail event detail.
    Handles various event sources and parameter structures.
    """
    # Try different parameter locations
    request_params = event_detail.get('requestParameters', {})
    response_elements = event_detail.get('responseElements', {})
    additional_event_data = event_detail.get('additionalEventData', {})
    
    # Common bucket name locations
    bucket_candidates = [
        request_params.get('bucketName'),
        request_params.get('bucket'),
        response_elements.get('bucketName'),
        response_elements.get('bucket'),
        additional_event_data.get('bucketName'),
        additional_event_data.get('bucket')
    ]
    
    # Return first non-None bucket name
    for bucket in bucket_candidates:
        if bucket:
            return bucket
    
    return None


def extract_security_group_id(event_detail: Dict[str, Any]) -> Optional[str]:
    """
    Extract security group ID from CloudTrail event detail.
    """
    request_params = event_detail.get('requestParameters', {})
    
    # Try different parameter locations for security group ID
    group_id_candidates = [
        request_params.get('groupId'),
        request_params.get('groupIdSet', [{}])[0].get('groupId') if request_params.get('groupIdSet') else None,
        request_params.get('groupIdSet', [{}])[0].get('groupId') if isinstance(request_params.get('groupIdSet'), list) else None
    ]
    
    for group_id in group_id_candidates:
        if group_id:
            return group_id
    
    return None


def remediate_s3_bucket(bucket: str) -> Dict[str, Any]:
    """
    S3 bucket remediation playbook.
    Enforces Public Access Block, sanitizes policy, and tags bucket.
    """
    start_time = time.time()
    results = {
        'bucket': bucket,
        'actions_taken': [],
        'success': True,
        'errors': []
    }
    
    try:
        # 1. Enforce Public Access Block
        if set_public_access_block(bucket):
            results['actions_taken'].append('enforced_public_access_block')
        
        # 2. Sanitize bucket policy
        if sanitize_bucket_policy(bucket):
            results['actions_taken'].append('sanitized_bucket_policy')
        
        # 3. Tag bucket as remediated
        if tag_bucket(bucket, 'driftguard:remediated', 'true'):
            results['actions_taken'].append('tagged_remediated')
        
        # Publish Security Hub finding
        publish_security_hub_finding('S3Bucket', bucket, 'S3 public access remediation')
        
        json_logger('INFO', 'S3 bucket remediation completed', 
                   bucket=bucket, actions=results['actions_taken'])
        
    except Exception as e:
        results['success'] = False
        results['errors'].append(str(e))
        json_logger('ERROR', 'S3 bucket remediation failed', 
                   bucket=bucket, error=str(e))
    
    # Record metrics
    latency_ms = int((time.time() - start_time) * 1000)
    put_metric('RemediationLatencyMs', latency_ms, 'Milliseconds')
    
    if results['success']:
        put_metric('RemediationSuccess', 1)
    else:
        put_metric('RemediationFailure', 1)
    
    return results


def remediate_security_group(group_id: str) -> Dict[str, Any]:
    """
    Security group remediation playbook.
    Removes dangerous rules, adds maintainer access, and tags group.
    """
    start_time = time.time()
    results = {
        'group_id': group_id,
        'actions_taken': [],
        'success': True,
        'errors': []
    }
    
    try:
        # 1. Describe security group
        security_group = describe_security_group(group_id)
        if not security_group:
            results['success'] = False
            results['errors'].append('Failed to describe security group')
            return results
        
        # 2. Revoke dangerous ingress rules
        revoked_count = revoke_dangerous_ingress(group_id, security_group)
        if revoked_count > 0:
            results['actions_taken'].append(f'revoked_{revoked_count}_dangerous_rules')
        
        # 3. Add maintainer access
        if authorize_maintainer_access(group_id):
            results['actions_taken'].append('added_maintainer_access')
        
        # 4. Tag security group as quarantined
        if tag_security_group(group_id, 'driftguard:quarantined', 'true'):
            results['actions_taken'].append('tagged_quarantined')
        
        # Publish Security Hub finding
        publish_security_hub_finding('SecurityGroup', group_id, 'Security group quarantine')
        
        json_logger('INFO', 'Security group remediation completed', 
                   group_id=group_id, actions=results['actions_taken'])
        
    except Exception as e:
        results['success'] = False
        results['errors'].append(str(e))
        json_logger('ERROR', 'Security group remediation failed', 
                   group_id=group_id, error=str(e))
    
    # Record metrics
    latency_ms = int((time.time() - start_time) * 1000)
    put_metric('RemediationLatencyMs', latency_ms, 'Milliseconds')
    
    if results['success']:
        put_metric('RemediationSuccess', 1)
    else:
        put_metric('RemediationFailure', 1)
    
    return results


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for DriftGuard auto-remediation.
    Routes CloudTrail events to appropriate remediation playbooks.
    """
    start_time = time.time()
    
    try:
        # Extract event details
        event_detail = event.get('detail', {})
        event_name = event_detail.get('eventName', '')
        event_source = event.get('source', '')
        
        json_logger('INFO', 'Processing CloudTrail event', 
                   event_name=event_name, event_source=event_source)
        
        results = []
        
        # Route to appropriate remediation playbook
        if event_source == 'aws.s3':
            bucket = extract_bucket_name(event_detail)
            if bucket:
                result = remediate_s3_bucket(bucket)
                results.append(result)
            else:
                json_logger('WARN', 'Could not extract bucket name from S3 event', 
                           event_detail=event_detail)
        
        elif event_source == 'aws.ec2':
            if event_name == 'AuthorizeSecurityGroupIngress':
                group_id = extract_security_group_id(event_detail)
                if group_id:
                    result = remediate_security_group(group_id)
                    results.append(result)
                else:
                    json_logger('WARN', 'Could not extract security group ID from EC2 event', 
                               event_detail=event_detail)
        
        # Log summary
        total_latency = int((time.time() - start_time) * 1000)
        json_logger('INFO', 'Lambda execution completed', 
                   total_latency_ms=total_latency, 
                   results_count=len(results),
                   results=results)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'DriftGuard remediation completed',
                'results': results,
                'execution_time_ms': total_latency
            })
        }
        
    except Exception as e:
        json_logger('ERROR', 'Lambda execution failed', error=str(e))
        put_metric('RemediationFailure', 1)
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'DriftGuard remediation failed',
                'message': str(e)
            })
        }
