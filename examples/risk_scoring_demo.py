#!/usr/bin/env python3
"""
IAM Identity Risk Scoring Demo

This script demonstrates the comprehensive IAM identity risk scoring capabilities,
including individual identity scoring, batch analysis, and interactive reporting.
"""

import json
import sys
import os
from datetime import datetime, timedelta

# Add the parent directory to the path to import airiam modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from airiam.analyzers.identity_risk_scorer import (
    IdentityRiskScorer, IdentityType, RiskFactor, IdentityRiskScore
)
from airiam.reporters.risk_score_reporter import RiskScoreReporter


def create_sample_identities():
    """Create sample IAM identity data for demonstration"""
    
    # High-risk user with admin access and no MFA
    high_risk_user = {
        "UserName": "admin-user",
        "Arn": "arn:aws:iam::123456789012:user/admin-user",
        "CreateDate": "2020-01-15T10:30:00Z",
        "PasswordLastUsed": "2024-01-10T14:20:00Z",
        "LoginProfileExists": True,
        "MFADevices": [],  # No MFA - high risk!
        "AttachedManagedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "PolicyVersionList": [{
                    "Document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*"
                            }
                        ]
                    }
                }]
            }
        ],
        "UserPolicyList": [
            {
                "PolicyName": "DangerousInlinePolicy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "iam:CreateRole",
                                "iam:AttachRolePolicy",
                                "iam:PassRole"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            }
        ],
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "CreateDate": "2022-06-01T08:00:00Z",
                "Status": "Active"
            }
        ],
        "LastAccessed": [
            {"ServiceNamespace": "s3", "LastAccessed": "2024-06-01T10:00:00Z"},
            {"ServiceNamespace": "ec2", "LastAccessed": None}  # Unused service
        ]
    }
    
    # Medium-risk role with some issues
    medium_risk_role = {
        "RoleName": "development-role",
        "Arn": "arn:aws:iam::123456789012:role/development-role",
        "CreateDate": "2023-03-20T09:15:00Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "AttachedManagedPolicies": [
            {
                "PolicyName": "S3FullAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
                "PolicyVersionList": [{
                    "Document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": "*"
                            }
                        ]
                    }
                }]
            }
        ],
        "RolePolicyList": [],
        "LastAccessed": [
            {"ServiceNamespace": "s3", "LastAccessed": "2024-06-10T14:30:00Z"},
            {"ServiceNamespace": "ec2", "LastAccessed": "2024-06-12T16:45:00Z"}
        ]
    }
    
    # Low-risk user with minimal permissions
    low_risk_user = {
        "UserName": "readonly-user",
        "Arn": "arn:aws:iam::123456789012:user/readonly-user",
        "CreateDate": "2024-01-10T11:00:00Z",
        "PasswordLastUsed": "2024-06-14T09:30:00Z",
        "LoginProfileExists": True,
        "MFADevices": [
            {
                "SerialNumber": "arn:aws:iam::123456789012:mfa/readonly-user",
                "Status": "Active",
                "EnableDate": "2024-01-10T11:30:00Z"
            }
        ],
        "AttachedManagedPolicies": [
            {
                "PolicyName": "ReadOnlyAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "PolicyVersionList": [{
                    "Document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:ListBucket",
                                    "ec2:DescribeInstances"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                }]
            }
        ],
        "UserPolicyList": [],
        "AccessKeyMetadata": [],
        "LastAccessed": [
            {"ServiceNamespace": "s3", "LastAccessed": "2024-06-14T08:00:00Z"},
            {"ServiceNamespace": "ec2", "LastAccessed": "2024-06-13T15:20:00Z"}
        ]
    }
    
    # Critical risk service account with cross-account access
    critical_risk_role = {
        "RoleName": "cross-account-service-role",
        "Arn": "arn:aws:iam::123456789012:role/cross-account-service-role",
        "CreateDate": "2019-06-01T10:00:00Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::999999999999:root",  # External account
                            "*"  # Very dangerous!
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "AttachedManagedPolicies": [
            {
                "PolicyName": "PowerUserAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess",
                "PolicyVersionList": [{
                    "Document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                                "NotAction": [
                                    "iam:*",
                                    "organizations:*"
                                ]
                            }
                        ]
                    }
                }]
            }
        ],
        "RolePolicyList": [
            {
                "PolicyName": "PrivilegeEscalationPolicy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "iam:*",
                                "lambda:CreateFunction",
                                "lambda:UpdateFunctionCode"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            }
        ],
        "LastAccessed": [
            {"ServiceNamespace": "lambda", "LastAccessed": "2023-12-01T10:00:00Z"},  # Very old
            {"ServiceNamespace": "s3", "LastAccessed": None}
        ]
    }
    
    return [high_risk_user, medium_risk_role, low_risk_user, critical_risk_role]


def demo_individual_scoring():
    """Demonstrate individual identity risk scoring"""
    print("\n🎯 INDIVIDUAL IDENTITY RISK SCORING")
    print("=" * 50)
    
    scorer = IdentityRiskScorer()
    identities = create_sample_identities()
    
    for i, identity in enumerate(identities, 1):
        print(f"\n📋 Analyzing Identity {i}:")
        
        # Score the identity
        risk_score = scorer.score_identity(identity)
        
        # Display results
        print(f"   Name: {risk_score.identity_name}")
        print(f"   Type: {risk_score.identity_type.value}")
        print(f"   Overall Risk Score: {risk_score.overall_score:.1f}/100")
        print(f"   Risk Level: {risk_score.risk_level}")
        
        # Show top 3 risk factors
        top_factors = sorted(
            risk_score.factor_scores.items(),
            key=lambda x: x[1].score * x[1].weight,
            reverse=True
        )[:3]
        
        print(f"   Top Risk Factors:")
        for factor, score in top_factors:
            if score.score > 10:  # Only show meaningful scores
                factor_name = factor.value.replace('_', ' ').title()
                print(f"     • {factor_name}: {score.score:.1f} - {score.details}")
        
        # Show top recommendation
        if risk_score.recommendations:
            print(f"   Primary Recommendation: {risk_score.recommendations[0]}")


def demo_batch_analysis():
    """Demonstrate batch analysis and ranking"""
    print("\n📊 BATCH ANALYSIS AND RANKING")
    print("=" * 50)
    
    scorer = IdentityRiskScorer()
    identities = create_sample_identities()
    
    # Score all identities
    scores = scorer.score_multiple_identities(identities)
    
    print(f"Analyzed {len(scores)} identities, ranked by risk:\n")
    
    # Display ranked results
    for i, score in enumerate(scores, 1):
        risk_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(score.risk_level, '⚪')
        
        print(f"{i}. {score.identity_name} ({score.identity_type.value})")
        print(f"   Score: {score.overall_score:.1f} {risk_emoji} {score.risk_level}")
        
        # Show highest contributing factor
        top_factor = max(
            score.factor_scores.items(),
            key=lambda x: x[1].score * x[1].weight
        )
        factor_name = top_factor[0].value.replace('_', ' ').title()
        print(f"   Main Issue: {factor_name} ({top_factor[1].score:.1f})")
        print()


def demo_summary_reporting():
    """Demonstrate summary statistics and reporting"""
    print("\n📈 SUMMARY STATISTICS AND REPORTING")
    print("=" * 50)
    
    scorer = IdentityRiskScorer()
    identities = create_sample_identities()
    
    # Score all identities
    scores = scorer.score_multiple_identities(identities)
    
    # Generate summary statistics
    summary_stats = scorer.generate_risk_summary_report(scores)
    
    print("📊 RISK DISTRIBUTION:")
    distribution = summary_stats['risk_level_distribution']
    for level, count in distribution.items():
        print(f"   {level}: {count} identities")
    
    print(f"\n📈 AVERAGE RISK SCORE: {summary_stats['average_risk_score']:.1f}/100")
    print(f"📉 RANGE: {summary_stats['lowest_risk_score']:.1f} - {summary_stats['highest_risk_score']:.1f}")
    
    print(f"\n⚠️  TOP RISK FACTORS:")
    factor_stats = summary_stats['factor_statistics']
    top_factors = sorted(
        factor_stats.items(),
        key=lambda x: x[1]['average_score'],
        reverse=True
    )[:3]
    
    for factor_name, stats in top_factors:
        clean_name = factor_name.replace('_', ' ').title()
        print(f"   • {clean_name}: {stats['average_score']:.1f} avg, {stats['high_risk_percentage']:.1f}% high risk")
    
    print(f"\n🎯 TOP RISKY IDENTITIES:")
    for identity in summary_stats['top_risky_identities']:
        print(f"   • {identity['name']} ({identity['type']}): {identity['score']:.1f} - {identity['risk_level']}")


def demo_detailed_factor_analysis():
    """Demonstrate detailed risk factor analysis"""
    print("\n🔍 DETAILED RISK FACTOR ANALYSIS")
    print("=" * 50)
    
    scorer = IdentityRiskScorer()
    identities = create_sample_identities()
    
    # Focus on the highest risk identity
    high_risk_identity = identities[3]  # The critical risk role
    risk_score = scorer.score_identity(high_risk_identity)
    
    print(f"🚨 ANALYZING: {risk_score.identity_name}")
    print(f"Overall Score: {risk_score.overall_score:.1f} ({risk_score.risk_level})\n")
    
    # Show all risk factors
    print("RISK FACTOR BREAKDOWN:")
    
    for factor, score in risk_score.factor_scores.items():
        factor_name = factor.value.replace('_', ' ').title()
        weighted_score = score.score * score.weight
        
        # Visual indicator
        if score.score >= 80:
            indicator = "🔴 CRITICAL"
        elif score.score >= 60:
            indicator = "🟠 HIGH"
        elif score.score >= 40:
            indicator = "🟡 MEDIUM"
        else:
            indicator = "🟢 LOW"
        
        print(f"\n{factor_name}:")
        print(f"   Score: {score.score:.1f}/100 (weight: {score.weight:.2f}) {indicator}")
        print(f"   Weighted Impact: {weighted_score:.1f}")
        print(f"   Details: {score.details}")
        
        if score.evidence:
            print(f"   Evidence: {', '.join(score.evidence[:2])}")
        
        if score.remediation:
            print(f"   Remediation: {score.remediation}")
    
    print(f"\n💡 RECOMMENDATIONS:")
    for i, rec in enumerate(risk_score.recommendations, 1):
        print(f"   {i}. {rec}")


def demo_reporting_outputs():
    """Demonstrate different reporting formats"""
    print("\n📋 REPORT GENERATION DEMO")
    print("=" * 50)
    
    scorer = IdentityRiskScorer()
    reporter = RiskScoreReporter(output_dir="demo_risk_reports")
    
    identities = create_sample_identities()
    scores = scorer.score_multiple_identities(identities)
    summary_stats = scorer.generate_risk_summary_report(scores)
    
    print("Generating reports in multiple formats...\n")
    
    # CLI Summary
    print("📺 CLI SUMMARY:")
    cli_summary = reporter.generate_cli_summary(scores, summary_stats)
    print(cli_summary)
    
    # Generate file outputs
    try:
        html_path = reporter.generate_html_dashboard(scores, summary_stats)
        print(f"✅ HTML Dashboard: {html_path}")
        
        json_path = reporter.export_json_report(scores, summary_stats)
        print(f"✅ JSON Export: {json_path}")
        
        csv_path = reporter.export_csv_report(scores)
        print(f"✅ CSV Export: {csv_path}")
        
        print(f"\n📁 All reports saved to: demo_risk_reports/")
        
    except Exception as e:
        print(f"❌ Error generating file reports: {e}")
    
    # Executive Summary
    print(f"\n👔 EXECUTIVE SUMMARY:")
    exec_summary = reporter.generate_executive_summary(summary_stats)
    print(exec_summary)


def demo_risk_factor_weights():
    """Demonstrate custom risk factor weighting"""
    print("\n⚖️  CUSTOM RISK FACTOR WEIGHTING")
    print("=" * 50)
    
    # Create custom weights that prioritize security violations
    from airiam.analyzers.identity_risk_scorer import RiskFactor
    
    security_focused_weights = {
        RiskFactor.POLICY_VIOLATIONS: 0.25,        # Increased
        RiskFactor.PRIVILEGE_ESCALATION: 0.25,     # Increased  
        RiskFactor.EXCESSIVE_PERMISSIONS: 0.20,    # Increased
        RiskFactor.UNUSED_ACCESS: 0.10,
        RiskFactor.STALE_CREDENTIALS: 0.05,
        RiskFactor.MFA_DISABLED: 0.05,
        RiskFactor.EXTERNAL_ACCESS: 0.05,
        RiskFactor.COMPLIANCE_VIOLATIONS: 0.03,
        RiskFactor.ADMIN_ACCESS: 0.01,
        RiskFactor.CROSS_ACCOUNT_ACCESS: 0.01
    }
    
    # Compare default vs custom scoring
    default_scorer = IdentityRiskScorer()
    security_scorer = IdentityRiskScorer(custom_weights=security_focused_weights)
    
    identities = create_sample_identities()
    risky_identity = identities[0]  # High-risk user
    
    default_score = default_scorer.score_identity(risky_identity)
    security_score = security_scorer.score_identity(risky_identity)
    
    print(f"Identity: {default_score.identity_name}")
    print(f"Default Scoring:          {default_score.overall_score:.1f} ({default_score.risk_level})")
    print(f"Security-Focused Scoring: {security_score.overall_score:.1f} ({security_score.risk_level})")
    
    print(f"\nDifference: {abs(security_score.overall_score - default_score.overall_score):.1f} points")
    
    if security_score.overall_score > default_score.overall_score:
        print("✨ Security-focused weighting identified higher risk")
    else:
        print("📊 Default weighting produced higher risk score")


def main():
    """Run all demonstration functions"""
    print("🚀 IAM IDENTITY RISK SCORING DEMONSTRATION")
    print("=" * 60)
    print("This demo showcases comprehensive risk scoring for IAM identities")
    print("including users, roles, and groups with detailed factor analysis.\n")
    
    try:
        demo_individual_scoring()
        demo_batch_analysis()
        demo_summary_reporting()
        demo_detailed_factor_analysis()
        demo_reporting_outputs()
        demo_risk_factor_weights()
        
        print("\n" + "=" * 60)
        print("✅ RISK SCORING DEMONSTRATION COMPLETE!")
        print("\nKey Features Demonstrated:")
        print("• Individual identity risk scoring (0-100 scale)")
        print("• 10 comprehensive risk factors")
        print("• Batch analysis and ranking")
        print("• Multiple report formats (HTML, JSON, CSV)")
        print("• Executive and CLI summaries")
        print("• Custom risk factor weighting")
        print("• Actionable remediation recommendations")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())