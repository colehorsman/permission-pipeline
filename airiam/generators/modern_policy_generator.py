"""
Modern IAM Policy Generator

This module implements advanced policy generation based on 2024 AWS IAM best practices,
including ABAC patterns, service-specific policies, and condition-constrained access.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AccessLevel(Enum):
    """Access levels for CRUD-based policy generation"""
    READ = "Read"
    WRITE = "Write"
    LIST = "List"
    TAGGING = "Tagging"
    PERMISSIONS_MANAGEMENT = "Permissions management"


class PolicyTemplate(Enum):
    """Common policy templates"""
    DEVELOPER_SANDBOX = "developer_sandbox"
    DATA_SCIENTIST = "data_scientist"
    SECURITY_AUDITOR = "security_auditor"
    COST_OPTIMIZER = "cost_optimizer"
    BACKUP_OPERATOR = "backup_operator"


@dataclass
class ServicePermissions:
    """Permissions for a specific AWS service"""
    service: str
    actions: List[str]
    resources: List[str]
    conditions: Optional[Dict[str, Any]] = None
    access_levels: Optional[List[AccessLevel]] = None


@dataclass
class PolicyGenerationConfig:
    """Configuration for policy generation"""
    policy_name: str
    description: str
    use_abac: bool = False
    tag_key: Optional[str] = None
    tag_value: Optional[str] = None
    enforce_mfa: bool = False
    restrict_regions: Optional[List[str]] = None
    time_restrictions: Optional[Dict[str, str]] = None
    ip_restrictions: Optional[List[str]] = None
    require_ssl: bool = True


class ModernPolicyGenerator:
    """
    Advanced IAM policy generator implementing 2024 best practices.
    
    Features:
    - ABAC (Attribute-Based Access Control) policies
    - Service-specific least-privilege policies
    - Condition-constrained access patterns
    - Template-based policy generation
    - Security controls integration
    """

    # Service action mappings for different access levels
    SERVICE_ACTION_MAPPINGS = {
        's3': {
            AccessLevel.READ: ['s3:GetObject', 's3:GetObjectVersion'],
            AccessLevel.WRITE: ['s3:PutObject', 's3:DeleteObject'],
            AccessLevel.LIST: ['s3:ListBucket', 's3:ListBucketVersions'],
            AccessLevel.TAGGING: ['s3:GetObjectTagging', 's3:PutObjectTagging'],
            AccessLevel.PERMISSIONS_MANAGEMENT: ['s3:PutBucketPolicy', 's3:PutBucketAcl']
        },
        'ec2': {
            AccessLevel.READ: ['ec2:DescribeInstances', 'ec2:DescribeImages'],
            AccessLevel.WRITE: ['ec2:RunInstances', 'ec2:TerminateInstances'],
            AccessLevel.LIST: ['ec2:DescribeInstances', 'ec2:DescribeVpcs'],
            AccessLevel.TAGGING: ['ec2:CreateTags', 'ec2:DeleteTags'],
            AccessLevel.PERMISSIONS_MANAGEMENT: ['ec2:ModifyInstanceAttribute']
        },
        'lambda': {
            AccessLevel.READ: ['lambda:GetFunction', 'lambda:GetFunctionConfiguration'],
            AccessLevel.WRITE: ['lambda:CreateFunction', 'lambda:UpdateFunctionCode'],
            AccessLevel.LIST: ['lambda:ListFunctions'],
            AccessLevel.TAGGING: ['lambda:TagResource', 'lambda:UntagResource'],
            AccessLevel.PERMISSIONS_MANAGEMENT: ['lambda:AddPermission', 'lambda:RemovePermission']
        },
        'dynamodb': {
            AccessLevel.READ: ['dynamodb:GetItem', 'dynamodb:Query'],
            AccessLevel.WRITE: ['dynamodb:PutItem', 'dynamodb:UpdateItem'],
            AccessLevel.LIST: ['dynamodb:Scan', 'dynamodb:ListTables'],
            AccessLevel.TAGGING: ['dynamodb:TagResource', 'dynamodb:UntagResource'],
            AccessLevel.PERMISSIONS_MANAGEMENT: ['dynamodb:UpdateTable']
        }
    }

    def __init__(self):
        """Initialize the modern policy generator"""
        self.generated_policies: List[Dict[str, Any]] = []

    def generate_abac_policy(self, config: PolicyGenerationConfig, 
                           service_permissions: List[ServicePermissions]) -> Dict[str, Any]:
        """
        Generate an Attribute-Based Access Control (ABAC) policy
        
        Args:
            config: Policy generation configuration
            service_permissions: List of service permissions to include
            
        Returns:
            ABAC policy document
        """
        if not config.use_abac or not config.tag_key:
            raise ValueError("ABAC configuration requires tag_key to be specified")

        statements = []
        
        for service_perm in service_permissions:
            statement = {
                "Sid": f"ABAC{service_perm.service.title()}Access",
                "Effect": "Allow",
                "Action": service_perm.actions,
                "Resource": service_perm.resources,
                "Condition": {
                    "StringEquals": {
                        f"aws:ResourceTag/{config.tag_key}": config.tag_value or "${aws:PrincipalTag/{config.tag_key}}"
                    }
                }
            }
            
            # Add additional conditions
            if service_perm.conditions:
                statement["Condition"].update(service_perm.conditions)
                
            statements.append(statement)

        # Add common security conditions
        statements = self._add_security_conditions(statements, config)

        policy = {
            "Version": "2012-10-17",
            "Statement": statements
        }

        return policy

    def generate_service_specific_policy(self, service: str, access_levels: List[AccessLevel],
                                       resources: Optional[List[str]] = None,
                                       config: Optional[PolicyGenerationConfig] = None) -> Dict[str, Any]:
        """
        Generate a service-specific least-privilege policy
        
        Args:
            service: AWS service name (e.g., 's3', 'ec2')
            access_levels: Required access levels
            resources: Specific resources to include
            config: Optional configuration for additional security controls
            
        Returns:
            Service-specific policy document
        """
        if service not in self.SERVICE_ACTION_MAPPINGS:
            raise ValueError(f"Service {service} not supported")

        service_mappings = self.SERVICE_ACTION_MAPPINGS[service]
        actions = []
        
        # Collect actions for requested access levels
        for access_level in access_levels:
            if access_level in service_mappings:
                actions.extend(service_mappings[access_level])

        # Default resources if not specified
        if not resources:
            resources = ["*"]

        statement = {
            "Sid": f"{service.title()}ServiceAccess",
            "Effect": "Allow",
            "Action": list(set(actions)),  # Remove duplicates
            "Resource": resources
        }

        statements = [statement]
        
        # Add security conditions if config provided
        if config:
            statements = self._add_security_conditions(statements, config)

        policy = {
            "Version": "2012-10-17",
            "Statement": statements
        }

        return policy

    def generate_condition_constrained_policy(self, actions: List[str], 
                                            resources: List[str],
                                            conditions: Dict[str, Any],
                                            config: Optional[PolicyGenerationConfig] = None) -> Dict[str, Any]:
        """
        Generate a policy with specific condition constraints
        
        Args:
            actions: List of IAM actions
            resources: List of resource ARNs
            conditions: IAM policy conditions
            config: Optional additional configuration
            
        Returns:
            Condition-constrained policy document
        """
        statement = {
            "Sid": "ConditionConstrainedAccess",
            "Effect": "Allow",
            "Action": actions,
            "Resource": resources,
            "Condition": conditions
        }

        statements = [statement]
        
        if config:
            statements = self._add_security_conditions(statements, config)

        policy = {
            "Version": "2012-10-17",
            "Statement": statements
        }

        return policy

    def generate_from_template(self, template: PolicyTemplate, 
                             config: PolicyGenerationConfig) -> Dict[str, Any]:
        """
        Generate a policy from a predefined template
        
        Args:
            template: Policy template to use
            config: Configuration for the policy
            
        Returns:
            Policy document based on template
        """
        if template == PolicyTemplate.DEVELOPER_SANDBOX:
            return self._generate_developer_sandbox_policy(config)
        elif template == PolicyTemplate.DATA_SCIENTIST:
            return self._generate_data_scientist_policy(config)
        elif template == PolicyTemplate.SECURITY_AUDITOR:
            return self._generate_security_auditor_policy(config)
        elif template == PolicyTemplate.COST_OPTIMIZER:
            return self._generate_cost_optimizer_policy(config)
        elif template == PolicyTemplate.BACKUP_OPERATOR:
            return self._generate_backup_operator_policy(config)
        else:
            raise ValueError(f"Template {template} not implemented")

    def generate_least_privilege_from_usage(self, cloudtrail_actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a least-privilege policy based on actual CloudTrail usage
        
        Args:
            cloudtrail_actions: List of actions from CloudTrail analysis
            
        Returns:
            Least-privilege policy document
        """
        # Group actions by service
        service_actions = {}
        for action_data in cloudtrail_actions:
            action = action_data.get('eventName', '')
            service = action_data.get('eventSource', '').replace('.amazonaws.com', '')
            
            if service not in service_actions:
                service_actions[service] = set()
            service_actions[service].add(action)

        statements = []
        
        for service, actions in service_actions.items():
            # Convert CloudTrail event names to IAM actions
            iam_actions = self._convert_cloudtrail_to_iam_actions(service, list(actions))
            
            if iam_actions:
                statement = {
                    "Sid": f"{service.title()}UsageBasedAccess",
                    "Effect": "Allow",
                    "Action": iam_actions,
                    "Resource": "*"  # Should be refined based on actual resources used
                }
                statements.append(statement)

        policy = {
            "Version": "2012-10-17",
            "Statement": statements
        }

        return policy

    def _generate_developer_sandbox_policy(self, config: PolicyGenerationConfig) -> Dict[str, Any]:
        """Generate a developer sandbox policy"""
        statements = [
            {
                "Sid": "DeveloperSandboxAccess",
                "Effect": "Allow",
                "Action": [
                    "ec2:Describe*",
                    "ec2:RunInstances",
                    "ec2:TerminateInstances",
                    "s3:*",
                    "lambda:*",
                    "dynamodb:*",
                    "logs:*"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": config.restrict_regions or ["us-east-1", "us-west-2"]
                    }
                }
            },
            {
                "Sid": "DenyProductionAccess",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceTag/Environment": ["production", "prod"]
                    }
                }
            }
        ]
        
        statements = self._add_security_conditions(statements, config)
        
        return {
            "Version": "2012-10-17",
            "Statement": statements
        }

    def _generate_data_scientist_policy(self, config: PolicyGenerationConfig) -> Dict[str, Any]:
        """Generate a data scientist policy"""
        statements = [
            {
                "Sid": "DataScientistS3Access",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::data-science-*",
                    "arn:aws:s3:::data-science-*/*"
                ]
            },
            {
                "Sid": "SageMakerAccess",
                "Effect": "Allow",
                "Action": [
                    "sagemaker:CreateNotebookInstance",
                    "sagemaker:DescribeNotebookInstance",
                    "sagemaker:StartNotebookInstance",
                    "sagemaker:StopNotebookInstance"
                ],
                "Resource": "*"
            },
            {
                "Sid": "DataScientistAthenaAccess",
                "Effect": "Allow",
                "Action": [
                    "athena:StartQueryExecution",
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults"
                ],
                "Resource": "*"
            }
        ]
        
        statements = self._add_security_conditions(statements, config)
        
        return {
            "Version": "2012-10-17",
            "Statement": statements
        }

    def _generate_security_auditor_policy(self, config: PolicyGenerationConfig) -> Dict[str, Any]:
        """Generate a security auditor policy"""
        statements = [
            {
                "Sid": "SecurityAuditorReadAccess",
                "Effect": "Allow",
                "Action": [
                    "iam:Get*",
                    "iam:List*",
                    "ec2:Describe*",
                    "s3:GetBucket*",
                    "s3:GetObject*",
                    "cloudtrail:Describe*",
                    "cloudtrail:Get*",
                    "config:Describe*",
                    "config:Get*",
                    "accessanalyzer:*"
                ],
                "Resource": "*"
            }
        ]
        
        statements = self._add_security_conditions(statements, config)
        
        return {
            "Version": "2012-10-17",
            "Statement": statements
        }

    def _generate_cost_optimizer_policy(self, config: PolicyGenerationConfig) -> Dict[str, Any]:
        """Generate a cost optimizer policy"""
        statements = [
            {
                "Sid": "CostOptimizerAccess",
                "Effect": "Allow",
                "Action": [
                    "ce:*",
                    "cur:*",
                    "budgets:*",
                    "ec2:DescribeInstances",
                    "ec2:DescribeReservedInstances",
                    "rds:DescribeDBInstances",
                    "s3:GetBucketLocation",
                    "s3:ListAllMyBuckets"
                ],
                "Resource": "*"
            }
        ]
        
        statements = self._add_security_conditions(statements, config)
        
        return {
            "Version": "2012-10-17",
            "Statement": statements
        }

    def _generate_backup_operator_policy(self, config: PolicyGenerationConfig) -> Dict[str, Any]:
        """Generate a backup operator policy"""
        statements = [
            {
                "Sid": "BackupOperatorAccess",
                "Effect": "Allow",
                "Action": [
                    "backup:*",
                    "backup-gateway:*",
                    "ec2:CreateSnapshot",
                    "ec2:DescribeSnapshots",
                    "rds:CreateDBSnapshot",
                    "rds:DescribeDBSnapshots",
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": "*"
            }
        ]
        
        statements = self._add_security_conditions(statements, config)
        
        return {
            "Version": "2012-10-17",
            "Statement": statements
        }

    def _add_security_conditions(self, statements: List[Dict[str, Any]], 
                                config: PolicyGenerationConfig) -> List[Dict[str, Any]]:
        """Add common security conditions to statements"""
        for statement in statements:
            if "Condition" not in statement:
                statement["Condition"] = {}

            # Add MFA requirement
            if config.enforce_mfa:
                statement["Condition"]["Bool"] = statement["Condition"].get("Bool", {})
                statement["Condition"]["Bool"]["aws:MultiFactorAuthPresent"] = "true"

            # Add region restrictions
            if config.restrict_regions:
                statement["Condition"]["StringEquals"] = statement["Condition"].get("StringEquals", {})
                statement["Condition"]["StringEquals"]["aws:RequestedRegion"] = config.restrict_regions

            # Add IP restrictions
            if config.ip_restrictions:
                statement["Condition"]["IpAddress"] = statement["Condition"].get("IpAddress", {})
                statement["Condition"]["IpAddress"]["aws:SourceIp"] = config.ip_restrictions

            # Require SSL
            if config.require_ssl:
                statement["Condition"]["Bool"] = statement["Condition"].get("Bool", {})
                statement["Condition"]["Bool"]["aws:SecureTransport"] = "true"

            # Add time restrictions
            if config.time_restrictions:
                if "start_time" in config.time_restrictions and "end_time" in config.time_restrictions:
                    statement["Condition"]["DateGreaterThan"] = statement["Condition"].get("DateGreaterThan", {})
                    statement["Condition"]["DateLessThan"] = statement["Condition"].get("DateLessThan", {})
                    statement["Condition"]["DateGreaterThan"]["aws:CurrentTime"] = config.time_restrictions["start_time"]
                    statement["Condition"]["DateLessThan"]["aws:CurrentTime"] = config.time_restrictions["end_time"]

        return statements

    def _convert_cloudtrail_to_iam_actions(self, service: str, cloudtrail_events: List[str]) -> List[str]:
        """Convert CloudTrail event names to IAM actions"""
        iam_actions = []
        
        for event in cloudtrail_events:
            # Basic conversion - CloudTrail events often map directly to IAM actions
            iam_action = f"{service}:{event}"
            iam_actions.append(iam_action)
            
        return iam_actions

    def validate_generated_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a generated policy for common issues
        
        Args:
            policy: Policy document to validate
            
        Returns:
            Validation results with warnings and errors
        """
        warnings = []
        errors = []
        
        # Check for wildcard actions
        for statement in policy.get("Statement", []):
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
                
            for action in actions:
                if action == "*":
                    warnings.append("Policy contains wildcard (*) action which is overly permissive")
                elif "*" in action and action != "*":
                    warnings.append(f"Action {action} contains wildcard which may be overly permissive")

            # Check for wildcard resources
            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
                
            for resource in resources:
                if resource == "*":
                    warnings.append("Policy contains wildcard (*) resource which is overly permissive")

        return {
            "is_valid": len(errors) == 0,
            "warnings": warnings,
            "errors": errors
        }