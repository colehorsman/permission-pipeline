"""
IAM Identity Risk Scorer

This module provides comprehensive risk scoring for IAM identities (users, roles, groups)
based on multiple security factors, compliance violations, and behavioral patterns.
"""

import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
import math

from .security_risk_analyzer import SecurityRiskAnalyzer, RiskLevel, RiskFinding

logger = logging.getLogger(__name__)


class IdentityType(Enum):
    """Types of IAM identities"""
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"


class RiskFactor(Enum):
    """Risk factors that contribute to identity risk score"""
    POLICY_VIOLATIONS = "POLICY_VIOLATIONS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    EXCESSIVE_PERMISSIONS = "EXCESSIVE_PERMISSIONS"
    UNUSED_ACCESS = "UNUSED_ACCESS"
    STALE_CREDENTIALS = "STALE_CREDENTIALS"
    MFA_DISABLED = "MFA_DISABLED"
    EXTERNAL_ACCESS = "EXTERNAL_ACCESS"
    COMPLIANCE_VIOLATIONS = "COMPLIANCE_VIOLATIONS"
    ADMIN_ACCESS = "ADMIN_ACCESS"
    CROSS_ACCOUNT_ACCESS = "CROSS_ACCOUNT_ACCESS"
    PROGRAMMATIC_ACCESS = "PROGRAMMATIC_ACCESS"
    CONSOLE_ACCESS = "CONSOLE_ACCESS"


@dataclass
class RiskFactorScore:
    """Individual risk factor score and details"""
    factor: RiskFactor
    score: float  # 0-100
    weight: float  # Weight in overall calculation
    details: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class IdentityRiskScore:
    """Complete risk score for an IAM identity"""
    identity_name: str
    identity_type: IdentityType
    identity_arn: str
    overall_score: float  # 0-100 (higher = more risky)
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    factor_scores: Dict[RiskFactor, RiskFactorScore]
    last_assessment: datetime
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'identity_name': self.identity_name,
            'identity_type': self.identity_type.value,
            'identity_arn': self.identity_arn,
            'overall_score': round(self.overall_score, 2),
            'risk_level': self.risk_level,
            'factor_scores': {
                factor.value: {
                    'score': round(score.score, 2),
                    'weight': score.weight,
                    'details': score.details,
                    'evidence': score.evidence,
                    'remediation': score.remediation
                }
                for factor, score in self.factor_scores.items()
            },
            'last_assessment': self.last_assessment.isoformat(),
            'recommendations': self.recommendations
        }


class IdentityRiskScorer:
    """
    Comprehensive risk scorer for IAM identities.
    
    Calculates risk scores based on:
    - Policy security violations
    - Privilege escalation potential
    - Excessive permissions
    - Usage patterns
    - Compliance violations
    - Security configuration
    """

    # Risk factor weights (must sum to 1.0)
    DEFAULT_WEIGHTS = {
        RiskFactor.POLICY_VIOLATIONS: 0.20,
        RiskFactor.PRIVILEGE_ESCALATION: 0.18,
        RiskFactor.EXCESSIVE_PERMISSIONS: 0.15,
        RiskFactor.UNUSED_ACCESS: 0.12,
        RiskFactor.STALE_CREDENTIALS: 0.10,
        RiskFactor.MFA_DISABLED: 0.08,
        RiskFactor.EXTERNAL_ACCESS: 0.07,
        RiskFactor.COMPLIANCE_VIOLATIONS: 0.05,
        RiskFactor.ADMIN_ACCESS: 0.03,
        RiskFactor.CROSS_ACCOUNT_ACCESS: 0.02
    }

    # Risk level thresholds
    RISK_THRESHOLDS = {
        'CRITICAL': 80,
        'HIGH': 60,
        'MEDIUM': 40,
        'LOW': 0
    }

    def __init__(self, custom_weights: Optional[Dict[RiskFactor, float]] = None):
        """
        Initialize the identity risk scorer
        
        Args:
            custom_weights: Optional custom weights for risk factors
        """
        self.weights = custom_weights or self.DEFAULT_WEIGHTS
        self.security_analyzer = SecurityRiskAnalyzer()
        
        # Validate weights sum to 1.0
        if abs(sum(self.weights.values()) - 1.0) > 0.01:
            raise ValueError("Risk factor weights must sum to 1.0")

    def score_identity(self, identity_data: Dict[str, Any], 
                      cloudtrail_data: Optional[List[Dict[str, Any]]] = None) -> IdentityRiskScore:
        """
        Calculate comprehensive risk score for an IAM identity
        
        Args:
            identity_data: IAM identity data (user, role, or group)
            cloudtrail_data: Optional CloudTrail data for usage analysis
            
        Returns:
            Complete risk score assessment
        """
        identity_type = self._determine_identity_type(identity_data)
        identity_name = self._get_identity_name(identity_data, identity_type)
        identity_arn = identity_data.get('Arn', '')
        
        factor_scores = {}
        
        # Calculate each risk factor score
        factor_scores[RiskFactor.POLICY_VIOLATIONS] = self._score_policy_violations(identity_data)
        factor_scores[RiskFactor.PRIVILEGE_ESCALATION] = self._score_privilege_escalation(identity_data)
        factor_scores[RiskFactor.EXCESSIVE_PERMISSIONS] = self._score_excessive_permissions(identity_data)
        factor_scores[RiskFactor.UNUSED_ACCESS] = self._score_unused_access(identity_data, cloudtrail_data)
        factor_scores[RiskFactor.STALE_CREDENTIALS] = self._score_stale_credentials(identity_data)
        factor_scores[RiskFactor.MFA_DISABLED] = self._score_mfa_status(identity_data)
        factor_scores[RiskFactor.EXTERNAL_ACCESS] = self._score_external_access(identity_data)
        factor_scores[RiskFactor.COMPLIANCE_VIOLATIONS] = self._score_compliance_violations(identity_data)
        factor_scores[RiskFactor.ADMIN_ACCESS] = self._score_admin_access(identity_data)
        factor_scores[RiskFactor.CROSS_ACCOUNT_ACCESS] = self._score_cross_account_access(identity_data)

        # Calculate weighted overall score
        overall_score = sum(
            score.score * self.weights[factor] 
            for factor, score in factor_scores.items()
        )

        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(factor_scores, risk_level)

        return IdentityRiskScore(
            identity_name=identity_name,
            identity_type=identity_type,
            identity_arn=identity_arn,
            overall_score=overall_score,
            risk_level=risk_level,
            factor_scores=factor_scores,
            last_assessment=datetime.utcnow(),
            recommendations=recommendations
        )

    def _score_policy_violations(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on policy security violations"""
        violations = []
        total_violations = 0
        high_severity_violations = 0
        
        # Analyze attached policies
        attached_policies = identity_data.get('AttachedManagedPolicies', [])
        inline_policies = identity_data.get('UserPolicyList', []) or identity_data.get('RolePolicyList', [])
        
        for policy in attached_policies:
            policy_doc = policy.get('PolicyVersionList', [{}])[0].get('Document')
            if policy_doc:
                findings = self.security_analyzer.analyze_policy(policy_doc, policy.get('PolicyName', ''))
                total_violations += len(findings)
                high_severity_violations += len([f for f in findings if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]])
                violations.extend([f.title for f in findings[:3]])  # Keep top 3
        
        for policy in inline_policies:
            policy_doc = policy.get('PolicyDocument')
            if policy_doc:
                findings = self.security_analyzer.analyze_policy(policy_doc, policy.get('PolicyName', ''))
                total_violations += len(findings)
                high_severity_violations += len([f for f in findings if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]])
                violations.extend([f.title for f in findings[:3]])
        
        # Calculate score (0-100)
        if total_violations == 0:
            score = 0
        else:
            # Score increases with violations, especially high-severity ones
            base_score = min(total_violations * 10, 70)
            severity_bonus = min(high_severity_violations * 15, 30)
            score = min(base_score + severity_bonus, 100)
        
        return RiskFactorScore(
            factor=RiskFactor.POLICY_VIOLATIONS,
            score=score,
            weight=self.weights[RiskFactor.POLICY_VIOLATIONS],
            details=f"Found {total_violations} policy violations ({high_severity_violations} high severity)",
            evidence=violations[:5],  # Top 5 violations
            remediation="Review and remediate policy violations according to security findings"
        )

    def _score_privilege_escalation(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on privilege escalation potential"""
        dangerous_actions = {
            'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy',
            'iam:CreateUser', 'iam:AttachUserPolicy', 'iam:PutUserPolicy',
            'iam:PassRole', 'lambda:CreateFunction', 'ec2:RunInstances'
        }
        
        found_actions = set()
        unrestricted_count = 0
        
        # Check attached and inline policies
        policies = identity_data.get('AttachedManagedPolicies', []) + identity_data.get('UserPolicyList', [])
        
        for policy in policies:
            policy_doc = policy.get('PolicyVersionList', [{}])[0].get('Document') or policy.get('PolicyDocument')
            if policy_doc:
                statements = policy_doc.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                
                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Check for dangerous actions
                        for action in actions:
                            if action == '*' or action in dangerous_actions:
                                found_actions.add(action)
                                
                                # Check if unrestricted (no conditions or broad resources)
                                resources = stmt.get('Resource', [])
                                conditions = stmt.get('Condition', {})
                                
                                if ('*' in resources or not conditions) and action in dangerous_actions:
                                    unrestricted_count += 1
        
        # Calculate score
        if not found_actions:
            score = 0
        else:
            base_score = len(found_actions) * 15
            unrestricted_penalty = unrestricted_count * 25
            score = min(base_score + unrestricted_penalty, 100)
        
        return RiskFactorScore(
            factor=RiskFactor.PRIVILEGE_ESCALATION,
            score=score,
            weight=self.weights[RiskFactor.PRIVILEGE_ESCALATION],
            details=f"Found {len(found_actions)} privilege escalation actions ({unrestricted_count} unrestricted)",
            evidence=list(found_actions)[:5],
            remediation="Restrict privilege escalation actions with conditions and specific resources"
        )

    def _score_excessive_permissions(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on excessive permissions"""
        wildcard_actions = 0
        wildcard_resources = 0
        total_actions = 0
        
        policies = identity_data.get('AttachedManagedPolicies', []) + identity_data.get('UserPolicyList', [])
        
        for policy in policies:
            policy_doc = policy.get('PolicyVersionList', [{}])[0].get('Document') or policy.get('PolicyDocument')
            if policy_doc:
                statements = policy_doc.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                
                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        actions = stmt.get('Action', [])
                        resources = stmt.get('Resource', [])
                        
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        
                        total_actions += len(actions)
                        
                        # Count wildcards
                        for action in actions:
                            if '*' in action:
                                wildcard_actions += 1
                        
                        for resource in resources:
                            if resource == '*':
                                wildcard_resources += 1
        
        # Calculate score
        if total_actions == 0:
            score = 0
            wildcard_ratio = 0.0
        else:
            wildcard_ratio = (wildcard_actions + wildcard_resources) / max(total_actions, 1)
            score = min(wildcard_ratio * 100, 100)
        
        return RiskFactorScore(
            factor=RiskFactor.EXCESSIVE_PERMISSIONS,
            score=score,
            weight=self.weights[RiskFactor.EXCESSIVE_PERMISSIONS],
            details=f"{wildcard_actions} wildcard actions, {wildcard_resources} wildcard resources out of {total_actions} total",
            evidence=[f"Wildcard usage ratio: {wildcard_ratio:.2%}"],
            remediation="Replace wildcard permissions with specific actions and resources"
        )

    def _score_unused_access(self, identity_data: Dict[str, Any], 
                           cloudtrail_data: Optional[List[Dict[str, Any]]]) -> RiskFactorScore:
        """Score based on unused access patterns"""
        last_used = identity_data.get('LastAccessed', [])
        
        if not last_used:
            # No usage data available
            return RiskFactorScore(
                factor=RiskFactor.UNUSED_ACCESS,
                score=50,  # Medium risk when no data available
                weight=self.weights[RiskFactor.UNUSED_ACCESS],
                details="No usage data available",
                evidence=["Missing LastAccessed data"],
                remediation="Enable service last accessed data collection"
            )
        
        # Calculate days since last access
        now = datetime.now()
        unused_services = 0
        total_services = len(last_used)
        oldest_access = now
        
        for service_access in last_used:
            last_access_date = service_access.get('LastAccessed')
            if last_access_date:
                if isinstance(last_access_date, str):
                    last_access_date = datetime.fromisoformat(last_access_date.replace('Z', '+00:00')).replace(tzinfo=None)
                elif hasattr(last_access_date, 'tzinfo') and last_access_date.tzinfo is not None:
                    last_access_date = last_access_date.replace(tzinfo=None)
                
                if last_access_date < oldest_access:
                    oldest_access = last_access_date
            else:
                unused_services += 1
        
        days_since_last_use = (now - oldest_access).days
        unused_ratio = unused_services / max(total_services, 1)
        
        # Calculate score (higher for more unused access)
        time_penalty = min(days_since_last_use / 90 * 50, 50)  # 0-50 based on 90+ days
        unused_penalty = unused_ratio * 50  # 0-50 based on unused services
        score = time_penalty + unused_penalty
        
        return RiskFactorScore(
            factor=RiskFactor.UNUSED_ACCESS,
            score=score,
            weight=self.weights[RiskFactor.UNUSED_ACCESS],
            details=f"{unused_services}/{total_services} services unused, {days_since_last_use} days since last activity",
            evidence=[f"Last activity: {oldest_access.strftime('%Y-%m-%d')}", f"Unused ratio: {unused_ratio:.1%}"],
            remediation="Remove unused permissions and services"
        )

    def _score_stale_credentials(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on credential staleness"""
        create_date = identity_data.get('CreateDate')
        password_last_used = identity_data.get('PasswordLastUsed')
        access_keys = identity_data.get('AccessKeyMetadata', [])
        
        if not create_date:
            return RiskFactorScore(
                factor=RiskFactor.STALE_CREDENTIALS,
                score=0,
                weight=self.weights[RiskFactor.STALE_CREDENTIALS],
                details="No credential information available",
                evidence=[],
                remediation=""
            )
        
        now = datetime.now()
        if isinstance(create_date, str):
            create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00')).replace(tzinfo=None)
        elif hasattr(create_date, 'tzinfo') and create_date.tzinfo is not None:
            create_date = create_date.replace(tzinfo=None)
        
        days_since_creation = (now - create_date).days
        
        stale_indicators = []
        score = 0
        
        # Check password age and usage
        if password_last_used:
            if isinstance(password_last_used, str):
                password_last_used = datetime.fromisoformat(password_last_used.replace('Z', '+00:00')).replace(tzinfo=None)
            elif hasattr(password_last_used, 'tzinfo') and password_last_used.tzinfo is not None:
                password_last_used = password_last_used.replace(tzinfo=None)
            days_since_password_use = (now - password_last_used).days
            
            if days_since_password_use > 90:
                score += 30
                stale_indicators.append(f"Password unused for {days_since_password_use} days")
        
        # Check access key age
        for key in access_keys:
            key_date = key.get('CreateDate')
            if key_date:
                if isinstance(key_date, str):
                    key_date = datetime.fromisoformat(key_date.replace('Z', '+00:00')).replace(tzinfo=None)
                elif hasattr(key_date, 'tzinfo') and key_date.tzinfo is not None:
                    key_date = key_date.replace(tzinfo=None)
                key_age = (now - key_date).days
                
                if key_age > 365:  # Over 1 year
                    score += 25
                    stale_indicators.append(f"Access key {key_age} days old")
                elif key_age > 180:  # Over 6 months
                    score += 15
                    stale_indicators.append(f"Access key {key_age} days old")
        
        # Account age factor
        if days_since_creation > 730:  # Over 2 years
            score += 10
            stale_indicators.append(f"Account {days_since_creation} days old")
        
        return RiskFactorScore(
            factor=RiskFactor.STALE_CREDENTIALS,
            score=min(score, 100),
            weight=self.weights[RiskFactor.STALE_CREDENTIALS],
            details=f"Account age: {days_since_creation} days, {len(stale_indicators)} stale indicators",
            evidence=stale_indicators,
            remediation="Rotate old credentials and remove unused access methods"
        )

    def _score_mfa_status(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on MFA configuration"""
        mfa_devices = identity_data.get('MFADevices', [])
        has_console_access = identity_data.get('LoginProfileExists', False)
        
        if not has_console_access:
            # No console access, MFA not critical
            return RiskFactorScore(
                factor=RiskFactor.MFA_DISABLED,
                score=0,
                weight=self.weights[RiskFactor.MFA_DISABLED],
                details="No console access, MFA not applicable",
                evidence=[],
                remediation=""
            )
        
        if not mfa_devices:
            return RiskFactorScore(
                factor=RiskFactor.MFA_DISABLED,
                score=100,
                weight=self.weights[RiskFactor.MFA_DISABLED],
                details="Console access enabled but no MFA devices configured",
                evidence=["No MFA devices", "Console access enabled"],
                remediation="Enable MFA for console access"
            )
        
        # Check MFA device status
        active_devices = [d for d in mfa_devices if d.get('Status') == 'Active']
        
        if len(active_devices) == 0:
            score = 80
            details = "MFA devices configured but none active"
        elif len(active_devices) == 1:
            score = 20
            details = "Single MFA device active"
        else:
            score = 0
            details = f"{len(active_devices)} MFA devices active"
        
        return RiskFactorScore(
            factor=RiskFactor.MFA_DISABLED,
            score=score,
            weight=self.weights[RiskFactor.MFA_DISABLED],
            details=details,
            evidence=[f"{len(active_devices)}/{len(mfa_devices)} MFA devices active"],
            remediation="Ensure MFA is properly configured and active" if score > 0 else ""
        )

    def _score_external_access(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on external access capabilities"""
        assume_role_policies = []
        cross_account_access = False
        
        # Check assume role policy for roles
        if 'AssumeRolePolicyDocument' in identity_data:
            assume_policy = identity_data['AssumeRolePolicyDocument']
            statements = assume_policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for stmt in statements:
                principals = stmt.get('Principal', {})
                if isinstance(principals, dict):
                    # Check for external principals
                    if 'AWS' in principals:
                        aws_principals = principals['AWS']
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        
                        for principal in aws_principals:
                            if ':' in principal and 'arn:aws:iam::' in principal:
                                # Extract account ID
                                account_id = principal.split(':')[4]
                                current_account = identity_data.get('Arn', '').split(':')[4]
                                
                                if account_id != current_account:
                                    cross_account_access = True
                                    assume_role_policies.append(principal)
        
        # Calculate score
        if cross_account_access:
            score = 60  # Medium-high risk for cross-account access
            details = f"Cross-account assume role access from {len(assume_role_policies)} external accounts"
            remediation = "Review cross-account access and add conditions to restrict usage"
        else:
            score = 0
            details = "No external access detected"
            remediation = ""
        
        return RiskFactorScore(
            factor=RiskFactor.EXTERNAL_ACCESS,
            score=score,
            weight=self.weights[RiskFactor.EXTERNAL_ACCESS],
            details=details,
            evidence=assume_role_policies[:3],  # Top 3 external principals
            remediation=remediation
        )

    def _score_compliance_violations(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on compliance violations"""
        violations = []
        score = 0
        
        # Check for admin access without MFA (SOC2 violation)
        has_admin_access = self._has_admin_access(identity_data)
        mfa_devices = identity_data.get('MFADevices', [])
        
        if has_admin_access and not mfa_devices:
            score += 40
            violations.append("Admin access without MFA (SOC2)")
        
        # Check for overly broad permissions (PCI-DSS)
        if self._has_wildcard_permissions(identity_data):
            score += 30
            violations.append("Wildcard permissions (PCI-DSS)")
        
        # Check for missing password policy compliance
        if identity_data.get('LoginProfileExists') and not self._meets_password_policy(identity_data):
            score += 20
            violations.append("Weak password policy (NIST)")
        
        # Check for stale access (GDPR/data retention)
        last_activity = self._get_last_activity_date(identity_data)
        if last_activity and (datetime.now() - last_activity).days > 365:
            score += 10
            violations.append("Stale access beyond retention period")
        
        return RiskFactorScore(
            factor=RiskFactor.COMPLIANCE_VIOLATIONS,
            score=min(score, 100),
            weight=self.weights[RiskFactor.COMPLIANCE_VIOLATIONS],
            details=f"{len(violations)} compliance violations detected",
            evidence=violations,
            remediation="Address compliance violations according to applicable frameworks"
        )

    def _score_admin_access(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on administrative access"""
        has_admin = self._has_admin_access(identity_data)
        
        if has_admin:
            # Admin access is inherently risky but necessary
            score = 70
            details = "Administrative access granted"
            remediation = "Ensure admin access is properly monitored and time-limited"
        else:
            score = 0
            details = "No administrative access"
            remediation = ""
        
        return RiskFactorScore(
            factor=RiskFactor.ADMIN_ACCESS,
            score=score,
            weight=self.weights[RiskFactor.ADMIN_ACCESS],
            details=details,
            evidence=["AdministratorAccess policy attached"] if has_admin else [],
            remediation=remediation
        )

    def _score_cross_account_access(self, identity_data: Dict[str, Any]) -> RiskFactorScore:
        """Score based on cross-account access capabilities"""
        # This is partially covered in external_access, but focuses on different aspects
        cross_account_policies = []
        
        policies = identity_data.get('AttachedManagedPolicies', []) + identity_data.get('UserPolicyList', [])
        
        for policy in policies:
            policy_doc = policy.get('PolicyVersionList', [{}])[0].get('Document') or policy.get('PolicyDocument')
            if policy_doc:
                # Look for sts:AssumeRole actions
                statements = policy_doc.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                
                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        if 'sts:AssumeRole' in actions:
                            resources = stmt.get('Resource', [])
                            if isinstance(resources, str):
                                resources = [resources]
                            
                            for resource in resources:
                                if 'arn:aws:iam::' in resource:
                                    cross_account_policies.append(resource)
        
        if cross_account_policies:
            score = 50
            details = f"Can assume roles in {len(set(cross_account_policies))} external accounts"
            remediation = "Review cross-account role assumption capabilities"
        else:
            score = 0
            details = "No cross-account access capabilities"
            remediation = ""
        
        return RiskFactorScore(
            factor=RiskFactor.CROSS_ACCOUNT_ACCESS,
            score=score,
            weight=self.weights[RiskFactor.CROSS_ACCOUNT_ACCESS],
            details=details,
            evidence=list(set(cross_account_policies))[:3],
            remediation=remediation
        )

    def _determine_identity_type(self, identity_data: Dict[str, Any]) -> IdentityType:
        """Determine the type of IAM identity"""
        if 'UserName' in identity_data:
            return IdentityType.USER
        elif 'RoleName' in identity_data:
            return IdentityType.ROLE
        elif 'GroupName' in identity_data:
            return IdentityType.GROUP
        else:
            raise ValueError("Unable to determine identity type")

    def _get_identity_name(self, identity_data: Dict[str, Any], identity_type: IdentityType) -> str:
        """Get the name of the identity"""
        if identity_type == IdentityType.USER:
            return identity_data.get('UserName', '')
        elif identity_type == IdentityType.ROLE:
            return identity_data.get('RoleName', '')
        elif identity_type == IdentityType.GROUP:
            return identity_data.get('GroupName', '')
        return ''

    def _has_admin_access(self, identity_data: Dict[str, Any]) -> bool:
        """Check if identity has administrative access"""
        policies = identity_data.get('AttachedManagedPolicies', [])
        
        for policy in policies:
            if 'AdministratorAccess' in policy.get('PolicyName', ''):
                return True
            
            # Check policy ARN
            if policy.get('PolicyArn') == 'arn:aws:iam::aws:policy/AdministratorAccess':
                return True
        
        return False

    def _has_wildcard_permissions(self, identity_data: Dict[str, Any]) -> bool:
        """Check if identity has wildcard permissions"""
        policies = identity_data.get('AttachedManagedPolicies', []) + identity_data.get('UserPolicyList', [])
        
        for policy in policies:
            policy_doc = policy.get('PolicyVersionList', [{}])[0].get('Document') or policy.get('PolicyDocument')
            if policy_doc:
                statements = policy_doc.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                
                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        if '*' in actions:
                            return True
        
        return False

    def _meets_password_policy(self, identity_data: Dict[str, Any]) -> bool:
        """Check if identity meets password policy requirements"""
        # This would typically check against account password policy
        # For now, return True as we don't have that data
        return True

    def _get_last_activity_date(self, identity_data: Dict[str, Any]) -> Optional[datetime]:
        """Get the last activity date for the identity"""
        password_last_used = identity_data.get('PasswordLastUsed')
        if password_last_used:
            if isinstance(password_last_used, str):
                return datetime.fromisoformat(password_last_used.replace('Z', '+00:00')).replace(tzinfo=None)
            elif hasattr(password_last_used, 'tzinfo') and password_last_used.tzinfo is not None:
                return password_last_used.replace(tzinfo=None)
            return password_last_used
        return None

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score"""
        for level, threshold in self.RISK_THRESHOLDS.items():
            if score >= threshold:
                return level
        return 'LOW'

    def _generate_recommendations(self, factor_scores: Dict[RiskFactor, RiskFactorScore], 
                                risk_level: str) -> List[str]:
        """Generate actionable recommendations based on risk factors"""
        recommendations = []
        
        # Get top risk factors (score > 50)
        high_risk_factors = [
            (factor, score) for factor, score in factor_scores.items() 
            if score.score > 50
        ]
        
        # Sort by weighted impact
        high_risk_factors.sort(key=lambda x: x[1].score * x[1].weight, reverse=True)
        
        # Add specific recommendations for top factors
        for factor, score in high_risk_factors[:3]:  # Top 3 recommendations
            if score.remediation:
                recommendations.append(f"{factor.value}: {score.remediation}")
        
        # Add general recommendations based on risk level
        if risk_level == 'CRITICAL':
            recommendations.append("URGENT: Review and restrict this identity immediately")
        elif risk_level == 'HIGH':
            recommendations.append("HIGH PRIORITY: Review within 24 hours")
        elif risk_level == 'MEDIUM':
            recommendations.append("Review within 1 week and implement improvements")
        
        return recommendations

    def score_multiple_identities(self, identities: List[Dict[str, Any]], 
                                 cloudtrail_data: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> List[IdentityRiskScore]:
        """
        Score multiple identities and return sorted by risk
        
        Args:
            identities: List of identity data
            cloudtrail_data: Optional dict mapping identity ARNs to CloudTrail data
            
        Returns:
            List of risk scores sorted by overall score (highest risk first)
        """
        scores = []
        
        for identity in identities:
            identity_arn = identity.get('Arn', '')
            trail_data = cloudtrail_data.get(identity_arn) if cloudtrail_data else None
            
            try:
                score = self.score_identity(identity, trail_data)
                scores.append(score)
            except Exception as e:
                logger.error(f"Failed to score identity {identity_arn}: {e}")
        
        # Sort by risk score (highest first)
        scores.sort(key=lambda x: x.overall_score, reverse=True)
        
        return scores

    def generate_risk_summary_report(self, scores: List[IdentityRiskScore]) -> Dict[str, Any]:
        """Generate a summary report of risk scores"""
        if not scores:
            return {"error": "No scores to analyze"}
        
        # Calculate statistics
        total_identities = len(scores)
        risk_level_counts = {}
        factor_stats = {}
        
        for score in scores:
            # Count risk levels
            risk_level_counts[score.risk_level] = risk_level_counts.get(score.risk_level, 0) + 1
            
            # Aggregate factor statistics
            for factor, factor_score in score.factor_scores.items():
                if factor not in factor_stats:
                    factor_stats[factor] = {'total': 0, 'count': 0, 'high_risk': 0}
                
                factor_stats[factor]['total'] += factor_score.score
                factor_stats[factor]['count'] += 1
                if factor_score.score > 70:
                    factor_stats[factor]['high_risk'] += 1
        
        # Calculate averages
        for factor in factor_stats:
            factor_stats[factor]['average'] = factor_stats[factor]['total'] / factor_stats[factor]['count']
        
        # Top risky identities
        top_risky = scores[:5]  # Top 5 riskiest
        
        return {
            'total_identities': total_identities,
            'risk_level_distribution': risk_level_counts,
            'average_risk_score': sum(s.overall_score for s in scores) / total_identities,
            'highest_risk_score': scores[0].overall_score if scores else 0,
            'lowest_risk_score': scores[-1].overall_score if scores else 0,
            'factor_statistics': {
                factor.value: {
                    'average_score': stats['average'],
                    'high_risk_count': stats['high_risk'],
                    'high_risk_percentage': (stats['high_risk'] / stats['count']) * 100
                }
                for factor, stats in factor_stats.items()
            },
            'top_risky_identities': [
                {
                    'name': score.identity_name,
                    'type': score.identity_type.value,
                    'score': score.overall_score,
                    'risk_level': score.risk_level
                }
                for score in top_risky
            ]
        }