#!/usr/bin/env python3
"""
Simple Modern IAM Analysis Demo (No AWS Dependencies)

This script demonstrates the modernized AirIAM security analysis capabilities
without requiring AWS credentials or boto3 installation.
"""

import json
import sys
import os

# Add the parent directory to the path to import airiam modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from airiam.analyzers.security_risk_analyzer import SecurityRiskAnalyzer, RiskLevel, RiskCategory
from airiam.generators.modern_policy_generator import (
    ModernPolicyGenerator, PolicyGenerationConfig, ServicePermissions, 
    AccessLevel, PolicyTemplate
)


def demo_security_analysis():
    """Demonstrate the security risk analyzer"""
    print("\n🔍 SECURITY RISK ANALYSIS")
    print("=" * 40)
    
    # Example of a problematic policy
    risky_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            {
                "Effect": "Allow", 
                "Action": [
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "s3:GetObject"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*"
            }
        ]
    }
    
    analyzer = SecurityRiskAnalyzer()
    findings = analyzer.analyze_policy(risky_policy, "ExampleRiskyPolicy")
    
    print(f"Analyzed policy and found {len(findings)} security risks:\n")
    
    for finding in findings:
        print(f"🚨 {finding.risk_level.value}: {finding.title}")
        print(f"   {finding.description}")
        print(f"   → {finding.remediation}\n")
    
    stats = analyzer.get_summary_stats()
    print(f"📊 Summary: {stats['high']} High, {stats['medium']} Medium risk findings")


def demo_modern_policy_generation():
    """Demonstrate modern policy generation"""
    print("\n🏗️  MODERN POLICY GENERATION")
    print("=" * 40)
    
    generator = ModernPolicyGenerator()
    
    # ABAC Policy
    print("1. ABAC Policy (Environment-based access):")
    
    config = PolicyGenerationConfig(
        policy_name="DeveloperABACPolicy",
        description="ABAC policy for developers",
        use_abac=True,
        tag_key="Environment",
        tag_value="development",
        enforce_mfa=True,
        restrict_regions=["us-east-1"]
    )
    
    service_permissions = [
        ServicePermissions(
            service="s3",
            actions=["s3:GetObject", "s3:PutObject"],
            resources=["arn:aws:s3:::dev-*/*"]
        )
    ]
    
    abac_policy = generator.generate_abac_policy(config, service_permissions)
    print(json.dumps(abac_policy, indent=2))
    
    # Service-specific policy
    print("\n2. Service-Specific Policy (S3 Read-Only):")
    
    s3_policy = generator.generate_service_specific_policy(
        service="s3",
        access_levels=[AccessLevel.READ, AccessLevel.LIST],
        resources=["arn:aws:s3:::data-*/*"]
    )
    print(json.dumps(s3_policy, indent=2))


def demo_template_policies():
    """Demonstrate template-based policy generation"""
    print("\n📋 TEMPLATE-BASED POLICIES")
    print("=" * 40)
    
    generator = ModernPolicyGenerator()
    
    config = PolicyGenerationConfig(
        policy_name="DataScientistPolicy",
        description="Policy for data science team",
        enforce_mfa=True
    )
    
    policy = generator.generate_from_template(PolicyTemplate.DATA_SCIENTIST, config)
    
    print("Data Scientist Policy Template:")
    print(json.dumps(policy, indent=2))


def main():
    """Run the demonstration"""
    print("🚀 MODERN AIRIAM SECURITY ANALYSIS DEMO")
    print("=" * 50)
    
    try:
        demo_security_analysis()
        demo_modern_policy_generation() 
        demo_template_policies()
        
        print("\n✅ DEMO COMPLETE!")
        print("\nModern AirIAM Features Demonstrated:")
        print("• Advanced security risk detection")
        print("• ABAC policy generation")
        print("• Service-specific least-privilege policies")
        print("• Template-based policy creation")
        print("• Comprehensive security controls")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())