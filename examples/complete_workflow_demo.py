#!/usr/bin/env python3
"""
Complete 4-Step IAM Risk Management Workflow Demo

This script demonstrates the complete end-to-end workflow:
1. Score real AWS identities
2. Generate executive reports
3. Track security improvements over time
4. Automate CI/CD risk monitoring

Usage:
    python examples/complete_workflow_demo.py --profile your-aws-profile
"""

import argparse
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add the parent directory to the path so we can import airiam modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from airiam.integrations.aws_risk_analyzer import AWSRiskAnalyzer
from airiam.reporters.executive_templates import ExecutiveReportGenerator
from airiam.tracking.improvement_tracker import SecurityImprovementTracker, create_default_goals
from airiam.cicd.risk_monitor import CICDRiskMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('complete_workflow.log')
    ]
)

logger = logging.getLogger(__name__)


def step1_score_real_identities(aws_profile: str = None) -> dict:
    """
    Step 1: Score real AWS identities
    
    Args:
        aws_profile: AWS profile to use
        
    Returns:
        Analysis results
    """
    print("\n" + "="*80)
    print("🎯 STEP 1: SCORING REAL AWS IDENTITIES")
    print("="*80)
    
    try:
        # Initialize AWS Risk Analyzer
        analyzer = AWSRiskAnalyzer(profile=aws_profile)
        
        # Show account info
        account_summary = analyzer.get_account_summary()
        print(f"📊 Connected to AWS Account: {account_summary['account_id']}")
        print(f"🔍 IAM Summary: {account_summary['iam_summary']['Users']} users, "
              f"{account_summary['iam_summary']['Roles']} roles")
        
        # Perform comprehensive analysis
        print("\n🚀 Performing comprehensive IAM risk analysis...")
        analysis_results = analyzer.analyze_account_risk(
            include_cloudtrail=True,
            output_dir=f"step1_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        # Display results
        summary = analysis_results['summary_statistics']
        print(f"\n📈 ANALYSIS COMPLETE!")
        print(f"   • Identities analyzed: {analysis_results['metadata']['identities_analyzed']}")
        print(f"   • Average risk score: {summary['average_risk_score']:.1f}/100")
        
        distribution = summary['risk_level_distribution']
        print(f"   • Critical risk: {distribution.get('CRITICAL', 0)} identities")
        print(f"   • High risk: {distribution.get('HIGH', 0)} identities")
        print(f"   • Medium risk: {distribution.get('MEDIUM', 0)} identities")
        print(f"   • Low risk: {distribution.get('LOW', 0)} identities")
        
        print(f"\n📁 Reports saved to: {analysis_results['report_paths']['html_dashboard']}")
        
        return analysis_results
        
    except Exception as e:
        logger.error(f"Step 1 failed: {e}")
        raise


def step2_generate_executive_reports(analysis_results: dict) -> dict:
    """
    Step 2: Generate executive reports
    
    Args:
        analysis_results: Results from step 1
        
    Returns:
        Generated report paths
    """
    print("\n" + "="*80)
    print("📊 STEP 2: GENERATING EXECUTIVE REPORTS")
    print("="*80)
    
    try:
        # Initialize Executive Report Generator
        exec_reporter = ExecutiveReportGenerator()
        
        # Generate board presentation
        print("📋 Generating board presentation...")
        board_presentation = exec_reporter.generate_board_presentation(analysis_results)
        
        # Generate compliance report
        print("📋 Generating compliance report...")
        compliance_report = exec_reporter.generate_compliance_report(
            analysis_results, 
            frameworks=['SOC2', 'PCI-DSS', 'HIPAA', 'GDPR']
        )
        
        # Generate business impact assessment
        print("📋 Generating business impact assessment...")
        business_impact = exec_reporter.generate_business_impact_assessment(analysis_results)
        
        # Save reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_dir = f"step2_executive_reports_{timestamp}"
        os.makedirs(report_dir, exist_ok=True)
        
        report_paths = {}
        
        # Save board presentation
        board_path = f"{report_dir}/board_presentation.txt"
        with open(board_path, 'w') as f:
            f.write(board_presentation)
        report_paths['board_presentation'] = board_path
        
        # Save compliance report
        compliance_path = f"{report_dir}/compliance_report.txt"
        with open(compliance_path, 'w') as f:
            f.write(compliance_report)
        report_paths['compliance_report'] = compliance_path
        
        # Save business impact assessment
        business_path = f"{report_dir}/business_impact_assessment.txt"
        with open(business_path, 'w') as f:
            f.write(business_impact)
        report_paths['business_impact'] = business_path
        
        print(f"\n✅ EXECUTIVE REPORTS GENERATED!")
        print(f"   📁 Board Presentation: {board_path}")
        print(f"   📁 Compliance Report: {compliance_path}")
        print(f"   📁 Business Impact: {business_path}")
        
        # Show key findings
        avg_score = analysis_results['summary_statistics']['average_risk_score']
        if avg_score >= 70:
            print(f"\n🚨 CRITICAL: Board attention required immediately!")
        elif avg_score >= 50:
            print(f"\n⚠️  HIGH: Executive oversight recommended")
        else:
            print(f"\n✅ MODERATE: Management review sufficient")
        
        return report_paths
        
    except Exception as e:
        logger.error(f"Step 2 failed: {e}")
        raise


def step3_track_security_improvements(analysis_results: dict) -> dict:
    """
    Step 3: Track security improvements over time
    
    Args:
        analysis_results: Results from step 1
        
    Returns:
        Tracking results
    """
    print("\n" + "="*80)
    print("📈 STEP 3: TRACKING SECURITY IMPROVEMENTS")
    print("="*80)
    
    try:
        # Initialize Security Improvement Tracker
        tracker = SecurityImprovementTracker()
        
        # Record the current assessment
        print("📊 Recording current security assessment...")
        assessment_id = tracker.record_assessment(analysis_results)
        print(f"   Assessment ID: {assessment_id}")
        
        # Create default security goals
        current_risk_score = analysis_results['summary_statistics']['average_risk_score']
        print(f"📋 Creating security improvement goals (current risk: {current_risk_score:.1f})...")
        
        goals = create_default_goals(tracker, current_risk_score)
        print(f"   Created {len(goals)} improvement goals")
        
        # Create sample improvement actions
        print("📝 Creating improvement actions...")
        critical_identities = analysis_results.get('risk_scores', [])
        critical_count = len([s for s in critical_identities if hasattr(s, 'total_score') and s.total_score >= 70])
        
        if critical_count > 0:
            # Create action for critical identities
            action1 = tracker.create_improvement_action(
                title="Remediate Critical Risk Identities",
                description=f"Address {critical_count} identities with critical risk levels",
                identity_target="Multiple critical identities",
                risk_factor="Overall Risk",
                assigned_to="Security Team",
                due_date=datetime.now() + timedelta(days=7),
                estimated_effort=critical_count * 2.0,  # 2 hours per identity
                impact_score=critical_count * 15.0  # 15 points per identity
            )
            print(f"   Created action: {action1.title}")
        
        # Create MFA enforcement action
        action2 = tracker.create_improvement_action(
            title="Enforce MFA for All Administrative Accounts",
            description="Implement MFA requirement for all admin-level access",
            identity_target="All administrative accounts",
            risk_factor="MFA",
            assigned_to="IAM Team",
            due_date=datetime.now() + timedelta(days=14),
            estimated_effort=8.0,
            impact_score=25.0
        )
        print(f"   Created action: {action2.title}")
        
        # Get progress overview
        print("\n📊 Current Progress Overview:")
        goal_progress = tracker.get_goal_progress()
        for goal in goal_progress:
            print(f"   🎯 {goal['title']}: {goal['progress_percentage']:.1f}% complete")
        
        action_dashboard = tracker.get_action_dashboard()
        print(f"\n📋 Action Items:")
        print(f"   • Total: {sum(action_dashboard['status_summary'].values())}")
        print(f"   • Completion Rate: {action_dashboard['completion_rate']:.1f}%")
        
        # Generate progress report
        print("\n📄 Generating progress report...")
        progress_report = tracker.generate_progress_report()
        
        # Save progress report
        report_path = f"step3_progress_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_path, 'w') as f:
            f.write(progress_report)
        
        print(f"✅ TRACKING SETUP COMPLETE!")
        print(f"   📁 Progress Report: {report_path}")
        
        return {
            'assessment_id': assessment_id,
            'goals_created': len(goals),
            'actions_created': 2,
            'progress_report': report_path,
            'tracker': tracker
        }
        
    except Exception as e:
        logger.error(f"Step 3 failed: {e}")
        raise


def step4_setup_cicd_monitoring(analysis_results: dict) -> dict:
    """
    Step 4: Automate CI/CD risk monitoring
    
    Args:
        analysis_results: Results from step 1
        
    Returns:
        Monitoring setup results
    """
    print("\n" + "="*80)
    print("🔄 STEP 4: SETTING UP CI/CD RISK MONITORING")
    print("="*80)
    
    try:
        # Initialize CI/CD Risk Monitor
        monitor = CICDRiskMonitor()
        
        # Generate monitoring configuration
        print("⚙️  Generating monitoring configuration...")
        config_path = monitor.generate_monitoring_config("demo_cicd_monitor_config.yaml")
        print(f"   Config saved to: {config_path}")
        
        # Test pipeline check
        print("\n🚀 Testing CI/CD pipeline integration...")
        pipeline_results = monitor.run_pipeline_check(fail_on_threshold=False)
        
        print(f"   Pipeline Status: {'✅ PASSED' if pipeline_results['passed'] else '❌ FAILED'}")
        print(f"   Alerts Generated: {len(pipeline_results.get('alerts', []))}")
        
        if pipeline_results.get('alerts'):
            print("   Alert Summary:")
            for alert in pipeline_results['alerts']:
                print(f"     • {alert['severity']}: {alert['message']}")
        
        # Show monitoring capabilities
        print(f"\n🔍 Monitoring Capabilities Configured:")
        print(f"   • Threshold-based alerting")
        print(f"   • Pipeline integration (GitHub Actions)")
        print(f"   • Automated issue creation")
        print(f"   • Slack/Teams notifications")
        print(f"   • Historical trend analysis")
        
        # Generate example GitHub Actions workflow
        workflow_path = ".github/workflows/security-monitoring.yml"
        if os.path.exists(workflow_path):
            print(f"   • GitHub Actions workflow: {workflow_path}")
        
        print(f"\n✅ CI/CD MONITORING SETUP COMPLETE!")
        print(f"   📁 Configuration: {config_path}")
        print(f"   🔄 Pipeline integration ready")
        
        return {
            'config_path': config_path,
            'pipeline_test': pipeline_results,
            'monitoring_enabled': True,
            'workflow_configured': os.path.exists(workflow_path)
        }
        
    except Exception as e:
        logger.error(f"Step 4 failed: {e}")
        raise


def main():
    """Main workflow execution"""
    parser = argparse.ArgumentParser(description='Complete IAM Risk Management Workflow Demo')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--skip-step', type=int, choices=[1, 2, 3, 4], 
                       help='Skip specific step (for testing)')
    parser.add_argument('--steps', nargs='+', type=int, choices=[1, 2, 3, 4],
                       help='Run only specific steps')
    
    args = parser.parse_args()
    
    print("🛡️  COMPLETE IAM RISK MANAGEMENT WORKFLOW")
    print("=" * 80)
    print("This demo will execute all 4 steps of the IAM risk management system:")
    print("1. Score real AWS identities")
    print("2. Generate executive reports")
    print("3. Track security improvements over time")
    print("4. Automate CI/CD risk monitoring")
    print("=" * 80)
    
    # Determine which steps to run
    if args.steps:
        steps_to_run = args.steps
    else:
        steps_to_run = [1, 2, 3, 4]
        if args.skip_step:
            steps_to_run.remove(args.skip_step)
    
    try:
        results = {}
        
        # Step 1: Score real AWS identities
        if 1 in steps_to_run:
            results['step1'] = step1_score_real_identities(args.profile)
        
        # Step 2: Generate executive reports
        if 2 in steps_to_run:
            if 'step1' in results:
                results['step2'] = step2_generate_executive_reports(results['step1'])
            else:
                print("⚠️  Skipping Step 2 - requires Step 1 results")
        
        # Step 3: Track security improvements
        if 3 in steps_to_run:
            if 'step1' in results:
                results['step3'] = step3_track_security_improvements(results['step1'])
            else:
                print("⚠️  Skipping Step 3 - requires Step 1 results")
        
        # Step 4: Setup CI/CD monitoring
        if 4 in steps_to_run:
            if 'step1' in results:
                results['step4'] = step4_setup_cicd_monitoring(results['step1'])
            else:
                # Can run step 4 independently
                print("ℹ️  Running Step 4 without Step 1 results (using mock data)")
                results['step4'] = step4_setup_cicd_monitoring({
                    'metadata': {'account_id': 'demo'},
                    'summary_statistics': {'average_risk_score': 45.0}
                })
        
        # Final summary
        print("\n" + "="*80)
        print("🎉 WORKFLOW COMPLETE!")
        print("="*80)
        
        for step_num, step_name in [(1, "Identity Scoring"), (2, "Executive Reports"), 
                                   (3, "Improvement Tracking"), (4, "CI/CD Monitoring")]:
            if step_num in steps_to_run and f'step{step_num}' in results:
                print(f"✅ Step {step_num}: {step_name} - Complete")
            elif step_num in steps_to_run:
                print(f"⚠️  Step {step_num}: {step_name} - Skipped")
            else:
                print(f"➖ Step {step_num}: {step_name} - Not requested")
        
        print(f"\n🎯 NEXT STEPS:")
        print(f"   1. Review generated reports and findings")
        print(f"   2. Implement recommended security improvements")
        print(f"   3. Set up regular monitoring schedule")
        print(f"   4. Integrate with your CI/CD pipeline")
        
        print(f"\n📚 For more information:")
        print(f"   • Check the generated reports in the output directories")
        print(f"   • Review the tracking database for progress monitoring")
        print(f"   • Configure the CI/CD monitoring for your environment")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Workflow interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Workflow failed: {e}")
        print(f"\n❌ WORKFLOW FAILED: {e}")
        return 1


if __name__ == "__main__":
    exit(main())