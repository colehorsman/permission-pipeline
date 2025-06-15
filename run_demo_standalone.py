#!/usr/bin/env python3
"""
Standalone demo that works without AWS credentials
"""

import sys
import os
sys.path.insert(0, '.')

from examples.demo_data import get_demo_analysis_results
from examples.complete_workflow_demo import (
    step2_generate_executive_reports, 
    step3_track_security_improvements, 
    step4_setup_cicd_monitoring
)

def main():
    print('🛡️  AIRIAM COMPLETE DEMO (All Steps)')
    print('=' * 60)
    print('Running complete demo with sample data...')
    print('(No AWS credentials required)')
    print()

    # Get demo data
    demo_results = get_demo_analysis_results()
    print(f'📊 Demo Account: {demo_results["metadata"]["account_id"]}')
    print(f'🎯 Identities: {demo_results["metadata"]["identities_analyzed"]}')
    print(f'📈 Risk Score: {demo_results["summary_statistics"]["average_risk_score"]:.1f}/100')
    print()

    try:
        # Clean up any existing database
        if os.path.exists('security_tracking.db'):
            os.remove('security_tracking.db')
        
        # Step 2: Executive Reports
        print('Running Step 2: Executive Reports...')
        step2_results = step2_generate_executive_reports(demo_results)
        print('✅ Step 2 Complete - Executive reports generated')
        print()
        
        # Step 3: Improvement Tracking
        print('Running Step 3: Improvement Tracking...')
        step3_results = step3_track_security_improvements(demo_results)
        print('✅ Step 3 Complete - Tracking system initialized')
        print()
        
        # Step 4: CI/CD Monitoring (mock mode)
        print('Running Step 4: CI/CD Monitoring...')
        step4_results = step4_setup_cicd_monitoring(demo_results)
        print('✅ Step 4 Complete - CI/CD monitoring configured')
        print()
        
        print('🎉 COMPLETE DEMO SUCCESSFUL!')
        print('=' * 60)
        print('✅ Executive reporting system ready')
        print('✅ Security improvement tracking operational') 
        print('✅ CI/CD monitoring pipeline configured')
        print('✅ GitHub Actions workflow available')
        print()
        print('📁 Generated Files:')
        for key, path in step2_results.items():
            print(f'   • {key}: {path}')
        print(f'   • Progress report: {step3_results["progress_report"]}')
        print(f'   • CI/CD config: {step4_results["config_path"]}')
        print(f'   • Tracking database: security_tracking.db')
        print()
        print('🎯 To analyze your real AWS account:')
        print('   1. Configure AWS credentials: aws configure')
        print('   2. Run: python3 examples/complete_workflow_demo.py --profile your-profile')
        
        return 0
        
    except Exception as e:
        print(f'❌ Demo failed: {e}')
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())