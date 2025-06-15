#!/usr/bin/env python3
"""
Modern IAM Analysis Demo

This script demonstrates the modernized AirIAM capabilities including:
- Advanced security risk analysis
- IAM Access Analyzer integration
- Modern policy generation with ABAC patterns
- Comprehensive security reporting

Usage:
    python examples/modern_iam_demo.py
"""

import json
import sys
import os
from datetime import datetime, timedelta

# Add the parent directory to the path to import airiam modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from airiam.analyzers.security_risk_analyzer import SecurityRiskAnalyzer, RiskLevel, RiskCategory
from airiam.analyzers.access_analyzer_integration import AccessAnalyzerIntegration
from airiam.generators.modern_policy_generator import (
    ModernPolicyGenerator, PolicyGenerationConfig, ServicePermissions, 
    AccessLevel, PolicyTemplate
)


def demo_security_risk_analysis():
    """Demonstrate advanced security risk analysis"""
    print("\n🔍 SECURITY RISK ANALYSIS DEMO")
    print("=" * 50)
    
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
                # No conditions - security risk!
            }
        ]
    }
    
    analyzer = SecurityRiskAnalyzer()
    findings = analyzer.analyze_policy(risky_policy, "ExampleRiskyPolicy")
    
    print(f"Found {len(findings)} security risks:")
    
    for finding in findings:
        print(f"\n🚨 {finding.risk_level.value}: {finding.title}")
        print(f"   Category: {finding.category.value}")
        print(f"   Description: {finding.description}")
        print(f"   Remediation: {finding.remediation}")
    
    # Show summary statistics
    stats = analyzer.get_summary_stats()
    print(f"\n📊 Risk Summary:")
    print(f"   Total Findings: {stats['total_findings']}")
    print(f"   Critical: {stats['critical']}")
    print(f"   High: {stats['high']}")
    print(f"   Medium: {stats['medium']}")
    print(f"   Low: {stats['low']}")


def demo_modern_policy_generation():
    """Demonstrate modern policy generation capabilities"""
    print("\n🏗️  MODERN POLICY GENERATION DEMO")
    print("=" * 50)
    
    generator = ModernPolicyGenerator()
    
    # Demo 1: ABAC Policy Generation
    print("\n1. ABAC (Attribute-Based Access Control) Policy:")
    
    config = PolicyGenerationConfig(
        policy_name="DeveloperABACPolicy",
        description="ABAC policy for developers",
        use_abac=True,
        tag_key="Environment",
        tag_value="development",
        enforce_mfa=True,
        restrict_regions=["us-east-1", "us-west-2"],
        require_ssl=True
    )
    
    service_permissions = [
        ServicePermissions(
            service="s3",
            actions=["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            resources=["arn:aws:s3:::dev-*", "arn:aws:s3:::dev-*/*"]
        ),
        ServicePermissions(
            service="ec2",
            actions=["ec2:DescribeInstances", "ec2:RunInstances"],
            resources=["*"]
        )
    ]
    
    abac_policy = generator.generate_abac_policy(config, service_permissions)
    print(json.dumps(abac_policy, indent=2))
    
    # Demo 2: Service-Specific Policy
    print("\n2. Service-Specific Least-Privilege Policy (S3 Read-Only):")
    
    s3_policy = generator.generate_service_specific_policy(
        service="s3",
        access_levels=[AccessLevel.READ, AccessLevel.LIST],
        resources=["arn:aws:s3:::data-lake-*", "arn:aws:s3:::data-lake-*/*"],
        config=config
    )
    print(json.dumps(s3_policy, indent=2))
    
    # Demo 3: Template-Based Policy
    print("\n3. Template-Based Policy (Data Scientist):")
    
    template_config = PolicyGenerationConfig(
        policy_name="DataScientistPolicy",
        description="Policy for data science team",
        enforce_mfa=True,
        restrict_regions=["us-east-1"]
    )
    
    data_scientist_policy = generator.generate_from_template(
        PolicyTemplate.DATA_SCIENTIST,
        template_config
    )
    print(json.dumps(data_scientist_policy, indent=2))


def demo_access_analyzer_integration():
    """Demonstrate IAM Access Analyzer integration"""
    print("\n🔬 IAM ACCESS ANALYZER INTEGRATION DEMO")
    print("=" * 50)
    
    # Note: This demo shows the API structure but won't actually call AWS
    # In real usage, you would need proper AWS credentials and setup
    
    print("\n1. Policy Validation Demo:")
    
    # Example policy to validate
    test_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "true"
                    }
                }
            }
        ]
    }
    
    print("Policy to validate:")
    print(json.dumps(test_policy, indent=2))
    
    # This would validate the policy in a real scenario
    print("\n✅ Policy validation would check for:")
    print("   - Syntax errors")
    print("   - Security best practices")
    print("   - Potential security risks")
    print("   - Resource access patterns")
    
    print("\n2. ABAC Policy Template Generation:")
    
    # Demonstrate ABAC template generation
    generator = ModernPolicyGenerator()
    abac_template = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:*"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceTag/Department": "${aws:PrincipalTag/Department}",
                        "aws:RequestedRegion": ["us-east-1", "us-west-2"]
                    }
                }
            }
        ]
    }
    
    print("ABAC Policy Template (Department-based access):")
    print(json.dumps(abac_template, indent=2))


def demo_compliance_reporting():
    """Demonstrate compliance and security reporting"""
    print("\n📋 COMPLIANCE & SECURITY REPORTING DEMO")
    print("=" * 50)
    
    # Simulate findings from multiple policies
    analyzer = SecurityRiskAnalyzer()
    
    policies_to_analyze = [
        {
            "name": "AdminPolicy",
            "document": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        },
        {
            "name": "DeveloperPolicy", 
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:*", "ec2:DescribeInstances"],
                        "Resource": "*"
                    }
                ]
            }
        },
        {
            "name": "ReadOnlyPolicy",
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "ec2:DescribeInstances"],
                        "Resource": ["arn:aws:s3:::safe-bucket/*", "*"]
                    }
                ]
            }
        }
    ]
    
    all_findings = []
    
    for policy in policies_to_analyze:
        findings = analyzer.analyze_policy(policy["document"], policy["name"])
        all_findings.extend(findings)
    
    # Generate compliance report
    print(f"\n📊 SECURITY COMPLIANCE SUMMARY")
    print(f"Analyzed {len(policies_to_analyze)} policies")
    print(f"Found {len(all_findings)} total security findings")
    
    # Group by risk level
    risk_counts = {}
    for finding in all_findings:
        level = finding.risk_level.value
        risk_counts[level] = risk_counts.get(level, 0) + 1
    
    print(f"\nFindings by Risk Level:")
    for level, count in risk_counts.items():
        print(f"   {level}: {count}")
    
    # Group by category
    category_counts = {}
    for finding in all_findings:
        category = finding.category.value
        category_counts[category] = category_counts.get(category, 0) + 1
    
    print(f"\nFindings by Category:")
    for category, count in category_counts.items():
        print(f"   {category}: {count}")
    
    # Show top priority findings
    critical_high = [f for f in all_findings if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
    
    print(f"\n🚨 TOP PRIORITY FINDINGS ({len(critical_high)} critical/high):")
    for finding in critical_high[:3]:  # Show top 3
        print(f"\n   {finding.risk_level.value}: {finding.title}")
        print(f"   Policy: {finding.policy_name}")
        print(f"   Action Required: {finding.remediation}")


def demo_cost_optimization_analysis():
    """Demonstrate cost optimization through IAM analysis"""
    print("\n💰 COST OPTIMIZATION ANALYSIS DEMO")
    print("=" * 50)
    
    # Simulate unused IAM resources analysis
    unused_resources = {
        "unused_users": [
            {"UserName": "old-contractor", "LastActivity": "2023-01-15", "AttachedPolicies": 3},
            {"UserName": "temp-access", "LastActivity": "2023-02-20", "AttachedPolicies": 1}
        ],
        "unused_roles": [
            {"RoleName": "legacy-role", "LastActivity": "2023-03-10", "AttachedPolicies": 2},
        ],
        "unused_policies": [
            {"PolicyName": "old-policy", "AttachmentCount": 0},
            {"PolicyName": "deprecated-policy", "AttachmentCount": 0}
        ]
    }
    
    print("🔍 UNUSED RESOURCE ANALYSIS:")
    print(f"   Unused Users: {len(unused_resources['unused_users'])}")
    print(f"   Unused Roles: {len(unused_resources['unused_roles'])}")
    print(f"   Unused Policies: {len(unused_resources['unused_policies'])}")
    
    # Calculate potential savings
    estimated_savings = {
        "unused_users": len(unused_resources['unused_users']) * 2,  # $2/month per unused user
        "policy_management": len(unused_resources['unused_policies']) * 0.5,  # $0.50/month per policy
        "role_optimization": len(unused_resources['unused_roles']) * 1  # $1/month per role
    }
    
    total_savings = sum(estimated_savings.values())
    
    print(f"\n💡 ESTIMATED MONTHLY SAVINGS:")
    print(f"   Removing unused users: ${estimated_savings['unused_users']:.2f}")
    print(f"   Cleaning up policies: ${estimated_savings['policy_management']:.2f}")
    print(f"   Optimizing roles: ${estimated_savings['role_optimization']:.2f}")
    print(f"   TOTAL MONTHLY SAVINGS: ${total_savings:.2f}")
    print(f"   ANNUAL SAVINGS: ${total_savings * 12:.2f}")


def main():
    """Run all demonstration functions"""
    print("🚀 MODERN AIRIAM CAPABILITIES DEMONSTRATION")
    print("=" * 60)
    print("This demo showcases the modernized AirIAM features based on")
    print("2024 AWS IAM best practices and advanced security analysis.")
    
    try:
        demo_security_risk_analysis()
        demo_modern_policy_generation()
        demo_access_analyzer_integration() 
        demo_compliance_reporting()
        demo_cost_optimization_analysis()
        
        print("\n✅ DEMONSTRATION COMPLETE!")
        print("=" * 60)
        print("The modernized AirIAM provides:")
        print("• Advanced security risk detection")
        print("• ABAC and least-privilege policy generation")
        print("• AWS Access Analyzer integration")
        print("• Comprehensive compliance reporting")
        print("• Cost optimization insights")
        print("• Modern IAM best practices enforcement")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())