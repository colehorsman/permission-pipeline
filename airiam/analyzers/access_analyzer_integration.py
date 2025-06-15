"""
IAM Access Analyzer Integration Module

This module integrates with AWS IAM Access Analyzer to provide modern policy analysis,
generation, and validation capabilities based on actual CloudTrail usage data.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class PolicyGenerationStatus(Enum):
    """Status of policy generation job"""
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED" 
    FAILED = "FAILED"


@dataclass
class PolicyGenerationResult:
    """Result of policy generation from Access Analyzer"""
    job_id: str
    status: PolicyGenerationStatus
    generated_policy: Optional[Dict[str, Any]]
    cloud_trail_details: Optional[Dict[str, Any]]
    error_message: Optional[str] = None


@dataclass
class ExternalAccessFinding:
    """Finding about external access to resources"""
    finding_id: str
    resource_arn: str
    resource_type: str
    condition: Dict[str, Any]
    action: List[str]
    principal: Dict[str, Any]
    is_public: bool
    external_principals: List[str]


@dataclass
class ValidationResult:
    """Result of policy validation"""
    is_valid: bool
    findings: List[Dict[str, Any]]
    warnings: List[str]
    errors: List[str]


class AccessAnalyzerIntegration:
    """
    Integration with AWS IAM Access Analyzer for modern IAM policy analysis.
    
    Provides capabilities for:
    - Generating least-privilege policies from CloudTrail data
    - Validating policies against AWS best practices
    - Detecting external access to resources
    - Custom policy checks
    """

    def __init__(self, session: Optional[boto3.Session] = None, region: str = 'us-east-1'):
        """
        Initialize Access Analyzer integration
        
        Args:
            session: Optional boto3 session to use
            region: AWS region for Access Analyzer
        """
        self.session = session or boto3.Session()
        self.region = region
        self.access_analyzer = self.session.client('accessanalyzer', region_name=region)
        self.iam = self.session.client('iam')
        
    def generate_least_privilege_policy(self, 
                                       principal_arn: str,
                                       cloudtrail_start_time: datetime,
                                       cloudtrail_end_time: datetime,
                                       service_namespace: Optional[str] = None) -> PolicyGenerationResult:
        """
        Generate a least-privilege policy based on CloudTrail usage data
        
        Args:
            principal_arn: ARN of the IAM user or role
            cloudtrail_start_time: Start time for CloudTrail analysis
            cloudtrail_end_time: End time for CloudTrail analysis  
            service_namespace: Optional service to focus on (e.g., 's3', 'ec2')
            
        Returns:
            PolicyGenerationResult with the generated policy
        """
        try:
            # Start policy generation job
            response = self.access_analyzer.start_policy_generation(
                policyGenerationDetails={
                    'principalArn': principal_arn
                },
                cloudTrailDetails={
                    'trails': [{
                        'cloudTrailArn': self._get_cloudtrail_arn(),
                        'regions': [self.region],
                        'allRegions': False
                    }],
                    'accessRole': self._get_access_role_arn(),
                    'startTime': cloudtrail_start_time,
                    'endTime': cloudtrail_end_time
                }
            )
            
            job_id = response['jobId']
            logger.info(f"Started policy generation job: {job_id}")
            
            # Poll for completion
            return self._wait_for_policy_generation(job_id)
            
        except ClientError as e:
            logger.error(f"Failed to start policy generation: {e}")
            return PolicyGenerationResult(
                job_id="",
                status=PolicyGenerationStatus.FAILED,
                generated_policy=None,
                cloud_trail_details=None,
                error_message=str(e)
            )

    def _wait_for_policy_generation(self, job_id: str, max_wait_time: int = 300) -> PolicyGenerationResult:
        """
        Wait for policy generation job to complete
        
        Args:
            job_id: The policy generation job ID
            max_wait_time: Maximum time to wait in seconds
            
        Returns:
            PolicyGenerationResult with the final status
        """
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            try:
                response = self.access_analyzer.get_generated_policy(jobId=job_id)
                
                status = PolicyGenerationStatus(response['jobDetails']['status'])
                
                if status == PolicyGenerationStatus.SUCCEEDED:
                    return PolicyGenerationResult(
                        job_id=job_id,
                        status=status,
                        generated_policy=response.get('generatedPolicyResult', {}).get('generatedPolicies'),
                        cloud_trail_details=response.get('jobDetails', {}).get('jobCreationDate')
                    )
                elif status == PolicyGenerationStatus.FAILED:
                    error_msg = response.get('jobDetails', {}).get('jobError', {}).get('message', 'Unknown error')
                    return PolicyGenerationResult(
                        job_id=job_id,
                        status=status,
                        generated_policy=None,
                        cloud_trail_details=None,
                        error_message=error_msg
                    )
                    
                # Still in progress, wait and retry
                time.sleep(10)
                
            except ClientError as e:
                logger.error(f"Error checking policy generation status: {e}")
                return PolicyGenerationResult(
                    job_id=job_id,
                    status=PolicyGenerationStatus.FAILED,
                    generated_policy=None,
                    cloud_trail_details=None,
                    error_message=str(e)
                )
        
        # Timeout
        return PolicyGenerationResult(
            job_id=job_id,
            status=PolicyGenerationStatus.FAILED,
            generated_policy=None,
            cloud_trail_details=None,
            error_message="Policy generation timed out"
        )

    def validate_policy_against_analyzer(self, policy_document: Dict[str, Any]) -> ValidationResult:
        """
        Validate a policy using IAM Access Analyzer validation APIs
        
        Args:
            policy_document: The IAM policy document to validate
            
        Returns:
            ValidationResult with validation findings
        """
        try:
            # Validate policy syntax and best practices
            response = self.access_analyzer.validate_policy(
                policyDocument=json.dumps(policy_document),
                policyType='IDENTITY_POLICY'
            )
            
            findings = response.get('findings', [])
            
            # Categorize findings
            errors = [f for f in findings if f['findingType'] == 'ERROR']
            warnings = [f for f in findings if f['findingType'] == 'WARNING']
            
            is_valid = len(errors) == 0
            
            return ValidationResult(
                is_valid=is_valid,
                findings=findings,
                warnings=[w.get('findingDetails', '') for w in warnings],
                errors=[e.get('findingDetails', '') for e in errors]
            )
            
        except ClientError as e:
            logger.error(f"Failed to validate policy: {e}")
            return ValidationResult(
                is_valid=False,
                findings=[],
                warnings=[],
                errors=[f"Validation failed: {str(e)}"]
            )

    def detect_external_access(self, analyzer_arn: str) -> List[ExternalAccessFinding]:
        """
        Detect resources that have external access using Access Analyzer
        
        Args:
            analyzer_arn: ARN of the Access Analyzer to use
            
        Returns:
            List of external access findings
        """
        external_findings = []
        
        try:
            paginator = self.access_analyzer.get_paginator('list_findings')
            
            for page in paginator.paginate(analyzerArn=analyzer_arn):
                for finding in page.get('findings', []):
                    if finding.get('status') == 'ACTIVE':
                        external_finding = ExternalAccessFinding(
                            finding_id=finding['id'],
                            resource_arn=finding['resource'],
                            resource_type=finding['resourceType'],
                            condition=finding.get('condition', {}),
                            action=finding.get('action', []),
                            principal=finding.get('principal', {}),
                            is_public=finding.get('isPublic', False),
                            external_principals=self._extract_external_principals(finding)
                        )
                        external_findings.append(external_finding)
                        
        except ClientError as e:
            logger.error(f"Failed to list findings: {e}")
            
        return external_findings

    def check_no_public_access(self, resource_arn: str, resource_type: str) -> bool:
        """
        Check if a resource policy grants public access
        
        Args:
            resource_arn: ARN of the resource to check
            resource_type: Type of AWS resource
            
        Returns:
            True if no public access, False if public access detected
        """
        try:
            response = self.access_analyzer.check_no_public_access(
                policyDocument=self._get_resource_policy(resource_arn, resource_type),
                resourceType=resource_type
            )
            
            return response.get('result') == 'PASS'
            
        except ClientError as e:
            logger.error(f"Failed to check public access for {resource_arn}: {e}")
            return False

    def check_access_not_granted(self, policy_document: Dict[str, Any], 
                                 actions: List[str], resources: List[str]) -> bool:
        """
        Check if a policy does NOT grant specific access
        
        Args:
            policy_document: The policy document to check
            actions: List of actions to check for
            resources: List of resources to check for
            
        Returns:
            True if access is NOT granted, False if access is granted
        """
        try:
            response = self.access_analyzer.check_access_not_granted(
                policyDocument=json.dumps(policy_document),
                access=[{
                    'actions': actions,
                    'resources': resources
                }],
                policyType='IDENTITY_POLICY'
            )
            
            return response.get('result') == 'PASS'
            
        except ClientError as e:
            logger.error(f"Failed to check access not granted: {e}")
            return False

    def generate_policy_from_cloudtrail_insights(self, 
                                                principal_arn: str,
                                                days_back: int = 90) -> Optional[Dict[str, Any]]:
        """
        Generate an optimized policy based on CloudTrail insights
        
        Args:
            principal_arn: ARN of the principal to analyze
            days_back: Number of days to look back in CloudTrail
            
        Returns:
            Generated policy document or None if generation failed
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)
        
        result = self.generate_least_privilege_policy(
            principal_arn=principal_arn,
            cloudtrail_start_time=start_time,
            cloudtrail_end_time=end_time
        )
        
        if result.status == PolicyGenerationStatus.SUCCEEDED:
            return result.generated_policy
        else:
            logger.error(f"Policy generation failed: {result.error_message}")
            return None

    def create_analyzer_if_not_exists(self, analyzer_name: str) -> str:
        """
        Create an Access Analyzer if it doesn't exist
        
        Args:
            analyzer_name: Name for the analyzer
            
        Returns:
            ARN of the analyzer
        """
        try:
            # Check if analyzer already exists
            response = self.access_analyzer.list_analyzers()
            
            for analyzer in response.get('analyzers', []):
                if analyzer['name'] == analyzer_name:
                    return analyzer['arn']
            
            # Create new analyzer
            response = self.access_analyzer.create_analyzer(
                analyzerName=analyzer_name,
                type='ACCOUNT'
            )
            
            return response['arn']
            
        except ClientError as e:
            logger.error(f"Failed to create analyzer: {e}")
            raise

    def _extract_external_principals(self, finding: Dict[str, Any]) -> List[str]:
        """Extract external principals from a finding"""
        principals = []
        principal_data = finding.get('principal', {})
        
        if 'AWS' in principal_data:
            aws_principals = principal_data['AWS']
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            principals.extend(aws_principals)
            
        return principals

    def _get_cloudtrail_arn(self) -> str:
        """Get the CloudTrail ARN to use for policy generation"""
        # This would typically be configured or discovered
        # For now, return a placeholder that should be configured
        account_id = self.session.client('sts').get_caller_identity()['Account']
        return f"arn:aws:cloudtrail:{self.region}:{account_id}:trail/airiam-policy-generation-trail"

    def _get_access_role_arn(self) -> str:
        """Get the IAM role ARN for CloudTrail access"""
        # This role needs to be created with appropriate permissions
        account_id = self.session.client('sts').get_caller_identity()['Account']
        return f"arn:aws:iam::{account_id}:role/AirIAM-AccessAnalyzer-Role"

    def _get_resource_policy(self, resource_arn: str, resource_type: str) -> str:
        """Get the resource policy for a given resource"""
        # This would implement getting resource policies for different resource types
        # Implementation would vary based on resource type (S3, Lambda, etc.)
        return "{}"  # Placeholder

    def generate_abac_policy_template(self, services: List[str], 
                                     tag_key: str, tag_value: str) -> Dict[str, Any]:
        """
        Generate an ABAC (Attribute-Based Access Control) policy template
        
        Args:
            services: List of AWS services to include
            tag_key: Tag key to use for access control
            tag_value: Tag value to match
            
        Returns:
            ABAC policy document template
        """
        actions = []
        for service in services:
            actions.extend([
                f"{service}:*"
            ])
            
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            f"aws:RequestedRegion": [self.region],
                            f"{tag_key}": tag_value
                        }
                    }
                }
            ]
        }
        
        return policy