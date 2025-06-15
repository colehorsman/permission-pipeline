"""
Modern Security Risk Analyzer for IAM Policies

This module implements comprehensive security risk analysis based on 2024 AWS IAM best practices,
incorporating findings from tools like Cloudsplaining, Policy Sentry, and AWS Security Hub.
"""

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Set, Optional, Any
import logging

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskCategory(Enum):
    """Categories of IAM security risks"""
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    RESOURCE_EXPOSURE = "RESOURCE_EXPOSURE"
    INFRASTRUCTURE_MODIFICATION = "INFRASTRUCTURE_MODIFICATION"
    OVERLY_PERMISSIVE = "OVERLY_PERMISSIVE"
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"


@dataclass
class RiskFinding:
    """Represents a security risk finding in an IAM policy"""
    risk_id: str
    title: str
    description: str
    risk_level: RiskLevel
    category: RiskCategory
    policy_name: str
    policy_arn: Optional[str]
    affected_statements: List[Dict[str, Any]]
    remediation: str
    references: List[str]
    compliance_frameworks: List[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format"""
        return {
            'risk_id': self.risk_id,
            'title': self.title,
            'description': self.description,
            'risk_level': self.risk_level.value,
            'category': self.category.value,
            'policy_name': self.policy_name,
            'policy_arn': self.policy_arn,
            'affected_statements': self.affected_statements,
            'remediation': self.remediation,
            'references': self.references,
            'compliance_frameworks': self.compliance_frameworks or []
        }


class SecurityRiskAnalyzer:
    """
    Advanced security risk analyzer for IAM policies based on 2024 best practices.
    
    Implements detection for:
    - Privilege escalation risks
    - Data exfiltration potential 
    - Resource exposure vulnerabilities
    - Infrastructure modification risks
    - Overly permissive policies
    - Compliance violations
    """

    # Dangerous actions that can lead to privilege escalation
    PRIVILEGE_ESCALATION_ACTIONS = {
        'iam:CreateRole',
        'iam:AttachRolePolicy', 
        'iam:PutRolePolicy',
        'iam:CreateUser',
        'iam:AttachUserPolicy',
        'iam:PutUserPolicy',
        'iam:AddUserToGroup',
        'iam:CreateGroup',
        'iam:AttachGroupPolicy',
        'iam:PutGroupPolicy',
        'iam:CreatePolicy',
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
        'iam:PassRole',
        'sts:AssumeRole',
        'lambda:CreateFunction',
        'lambda:UpdateFunctionCode',
        'lambda:InvokeFunction',
        'ec2:RunInstances',
        'ecs:RunTask',
        'glue:CreateDevEndpoint'
    }

    # Actions that can lead to data exfiltration
    DATA_EXFILTRATION_ACTIONS = {
        's3:GetObject',
        's3:ListBucket', 
        'rds:DescribeDBInstances',
        'rds:DescribeDBClusters',
        'dynamodb:Scan',
        'dynamodb:Query',
        'secretsmanager:GetSecretValue',
        'ssm:GetParameter',
        'ssm:GetParameters',
        'ssm:GetParametersByPath',
        'kms:Decrypt',
        'lambda:GetFunction',
        'ec2:GetConsoleOutput',
        'ec2:GetConsoleScreenshot',
        'logs:CreateExportTask',
        'rds:DownloadDBLogFilePortion'
    }

    # Actions that can expose resources publicly
    RESOURCE_EXPOSURE_ACTIONS = {
        's3:PutBucketPolicy',
        's3:PutBucketAcl',
        's3:PutObjectAcl',
        'ec2:AuthorizeSecurityGroupIngress',
        'ec2:CreateSecurityGroup',
        'rds:ModifyDBInstance',
        'rds:ModifyDBCluster',
        'lambda:AddPermission',
        'sns:AddPermission',
        'sqs:AddPermission',
        'kms:CreateGrant',
        'kms:PutKeyPolicy'
    }

    # Actions for infrastructure modification
    INFRASTRUCTURE_MODIFICATION_ACTIONS = {
        'ec2:TerminateInstances',
        'ec2:StopInstances', 
        'rds:DeleteDBInstance',
        'rds:DeleteDBCluster',
        's3:DeleteBucket',
        'lambda:DeleteFunction',
        'dynamodb:DeleteTable',
        'cloudformation:DeleteStack',
        'ec2:DeleteVpc',
        'ec2:DeleteSubnet'
    }

    def __init__(self):
        """Initialize the security risk analyzer"""
        self.findings: List[RiskFinding] = []

    def analyze_policy(self, policy_document: Dict[str, Any], policy_name: str, 
                      policy_arn: Optional[str] = None) -> List[RiskFinding]:
        """
        Perform comprehensive security analysis on an IAM policy
        
        Args:
            policy_document: The IAM policy document to analyze
            policy_name: Name of the policy
            policy_arn: ARN of the policy (if available)
            
        Returns:
            List of security risk findings
        """
        self.findings = []
        
        try:
            # Validate policy structure
            if not self._validate_policy_structure(policy_document):
                return self.findings

            # Run all security analyses
            self._analyze_privilege_escalation_risks(policy_document, policy_name, policy_arn)
            self._analyze_data_exfiltration_risks(policy_document, policy_name, policy_arn) 
            self._analyze_resource_exposure_risks(policy_document, policy_name, policy_arn)
            self._analyze_overly_permissive_policies(policy_document, policy_name, policy_arn)
            self._analyze_compliance_violations(policy_document, policy_name, policy_arn)
            
        except Exception as e:
            logger.error(f"Error analyzing policy {policy_name}: {str(e)}")
            
        return self.findings

    def _validate_policy_structure(self, policy_document: Dict[str, Any]) -> bool:
        """Validate that the policy document has the expected structure"""
        if not isinstance(policy_document, dict):
            return False
        if 'Statement' not in policy_document:
            return False
        return True

    def _analyze_privilege_escalation_risks(self, policy_document: Dict[str, Any], 
                                          policy_name: str, policy_arn: Optional[str]) -> None:
        """Analyze for privilege escalation risks"""
        statements = self._get_statements(policy_document)
        
        for i, statement in enumerate(statements):
            if statement.get('Effect') != 'Allow':
                continue
                
            actions = self._get_actions_from_statement(statement)
            resources = self._get_resources_from_statement(statement)
            
            # Check for dangerous action combinations
            dangerous_actions = actions.intersection(self.PRIVILEGE_ESCALATION_ACTIONS)
            
            if dangerous_actions:
                # Check if resources are overly broad
                if self._has_overly_broad_resources(resources):
                    self._add_finding(
                        risk_id="PRIV_ESC_001",
                        title="Privilege Escalation Risk - Dangerous Actions with Broad Resources",
                        description=f"Policy allows dangerous actions {list(dangerous_actions)} on overly broad resources",
                        risk_level=RiskLevel.HIGH,
                        category=RiskCategory.PRIVILEGE_ESCALATION,
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                        affected_statements=[statement],
                        remediation="Restrict resources to specific ARNs and add condition constraints",
                        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"]
                    )

            # Check for iam:PassRole without conditions
            if 'iam:PassRole' in actions:
                conditions = statement.get('Condition', {})
                if not conditions:
                    self._add_finding(
                        risk_id="PRIV_ESC_002", 
                        title="iam:PassRole Without Conditions",
                        description="Policy allows iam:PassRole without condition constraints",
                        risk_level=RiskLevel.MEDIUM,
                        category=RiskCategory.PRIVILEGE_ESCALATION,
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                        affected_statements=[statement],
                        remediation="Add StringEquals condition to restrict which services can assume the role",
                        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"]
                    )

    def _analyze_data_exfiltration_risks(self, policy_document: Dict[str, Any],
                                        policy_name: str, policy_arn: Optional[str]) -> None:
        """Analyze for data exfiltration risks"""
        statements = self._get_statements(policy_document)
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
                
            actions = self._get_actions_from_statement(statement)
            resources = self._get_resources_from_statement(statement)
            
            # Check for data access actions without resource constraints
            data_actions = actions.intersection(self.DATA_EXFILTRATION_ACTIONS)
            
            if data_actions and self._has_overly_broad_resources(resources):
                self._add_finding(
                    risk_id="DATA_EX_001",
                    title="Data Exfiltration Risk - Broad Data Access",
                    description=f"Policy allows data access actions {list(data_actions)} on overly broad resources",
                    risk_level=RiskLevel.HIGH,
                    category=RiskCategory.DATA_EXFILTRATION,
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    affected_statements=[statement],
                    remediation="Restrict resources to specific buckets, databases, or parameters needed",
                    references=["https://aws.amazon.com/blogs/security/techniques-for-writing-least-privilege-iam-policies/"]
                )

    def _analyze_resource_exposure_risks(self, policy_document: Dict[str, Any],
                                        policy_name: str, policy_arn: Optional[str]) -> None:
        """Analyze for resource exposure risks"""
        statements = self._get_statements(policy_document)
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
                
            actions = self._get_actions_from_statement(statement)
            
            # Check for actions that can make resources public
            exposure_actions = actions.intersection(self.RESOURCE_EXPOSURE_ACTIONS)
            
            if exposure_actions:
                self._add_finding(
                    risk_id="RES_EXP_001",
                    title="Resource Exposure Risk - Public Access Actions",
                    description=f"Policy allows actions {list(exposure_actions)} that can expose resources publicly",
                    risk_level=RiskLevel.MEDIUM,
                    category=RiskCategory.RESOURCE_EXPOSURE,
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    affected_statements=[statement],
                    remediation="Add condition constraints to prevent public access or restrict to specific principals",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"]
                )

    def _analyze_overly_permissive_policies(self, policy_document: Dict[str, Any],
                                           policy_name: str, policy_arn: Optional[str]) -> None:
        """Analyze for overly permissive policies"""
        statements = self._get_statements(policy_document)
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
                
            actions = self._get_actions_from_statement(statement)
            resources = self._get_resources_from_statement(statement)
            
            # Check for wildcard actions
            if '*' in actions or any('*' in action for action in actions):
                self._add_finding(
                    risk_id="PERM_001",
                    title="Overly Permissive - Wildcard Actions",
                    description="Policy uses wildcard (*) in actions, granting excessive permissions",
                    risk_level=RiskLevel.HIGH,
                    category=RiskCategory.OVERLY_PERMISSIVE,
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    affected_statements=[statement],
                    remediation="Replace wildcard actions with specific actions required for the use case",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"]
                )

            # Check for wildcard resources
            if '*' in resources:
                self._add_finding(
                    risk_id="PERM_002", 
                    title="Overly Permissive - Wildcard Resources",
                    description="Policy uses wildcard (*) in resources, allowing access to all resources",
                    risk_level=RiskLevel.MEDIUM,
                    category=RiskCategory.OVERLY_PERMISSIVE,
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    affected_statements=[statement],
                    remediation="Specify exact resource ARNs or use ARN patterns with variables",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns"]
                )

    def _analyze_compliance_violations(self, policy_document: Dict[str, Any],
                                      policy_name: str, policy_arn: Optional[str]) -> None:
        """Analyze for compliance framework violations"""
        statements = self._get_statements(policy_document)
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
                
            # Check for missing MFA requirements on sensitive actions
            actions = self._get_actions_from_statement(statement)
            conditions = statement.get('Condition', {})
            
            sensitive_actions = {'iam:*', 'ec2:TerminateInstances', 's3:DeleteBucket'}
            if actions.intersection(sensitive_actions) and not self._has_mfa_condition(conditions):
                self._add_finding(
                    risk_id="COMP_001",
                    title="Compliance Violation - Missing MFA for Sensitive Actions", 
                    description="Sensitive actions allowed without MFA requirement",
                    risk_level=RiskLevel.MEDIUM,
                    category=RiskCategory.COMPLIANCE_VIOLATION,
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    affected_statements=[statement],
                    remediation="Add condition requiring MFA for sensitive operations",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html"],
                    compliance_frameworks=["SOC2", "PCI-DSS"]
                )

    def _get_statements(self, policy_document: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract statements from policy document"""
        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        return statements

    def _get_actions_from_statement(self, statement: Dict[str, Any]) -> Set[str]:
        """Extract actions from a policy statement"""
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        return set(actions)

    def _get_resources_from_statement(self, statement: Dict[str, Any]) -> Set[str]:
        """Extract resources from a policy statement"""
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        return set(resources)

    def _has_overly_broad_resources(self, resources: Set[str]) -> bool:
        """Check if resources are overly broad (wildcards)"""
        return '*' in resources or any(resource.endswith('*') for resource in resources)

    def _has_mfa_condition(self, conditions: Dict[str, Any]) -> bool:
        """Check if policy has MFA condition"""
        for condition_type, condition_values in conditions.items():
            if 'aws:MultiFactorAuthPresent' in condition_values:
                return True
        return False

    def _add_finding(self, risk_id: str, title: str, description: str, risk_level: RiskLevel,
                    category: RiskCategory, policy_name: str, policy_arn: Optional[str],
                    affected_statements: List[Dict[str, Any]], remediation: str,
                    references: List[str], compliance_frameworks: Optional[List[str]] = None) -> None:
        """Add a risk finding to the results"""
        finding = RiskFinding(
            risk_id=risk_id,
            title=title,
            description=description,
            risk_level=risk_level,
            category=category,
            policy_name=policy_name,
            policy_arn=policy_arn,
            affected_statements=affected_statements,
            remediation=remediation,
            references=references,
            compliance_frameworks=compliance_frameworks
        )
        self.findings.append(finding)

    def get_findings_by_risk_level(self, risk_level: RiskLevel) -> List[RiskFinding]:
        """Get findings filtered by risk level"""
        return [f for f in self.findings if f.risk_level == risk_level]

    def get_findings_by_category(self, category: RiskCategory) -> List[RiskFinding]:
        """Get findings filtered by category"""
        return [f for f in self.findings if f.category == category]

    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics of findings"""
        stats = {
            'total_findings': len(self.findings),
            'critical': len(self.get_findings_by_risk_level(RiskLevel.CRITICAL)),
            'high': len(self.get_findings_by_risk_level(RiskLevel.HIGH)),
            'medium': len(self.get_findings_by_risk_level(RiskLevel.MEDIUM)),
            'low': len(self.get_findings_by_risk_level(RiskLevel.LOW))
        }
        return stats