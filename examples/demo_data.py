"""
Demo data for testing the complete workflow without AWS credentials
"""

from datetime import datetime

def get_demo_analysis_results():
    """Generate demo analysis results for testing"""
    return {
        'metadata': {
            'account_id': '123456789012',
            'analysis_date': datetime.now().isoformat(),
            'profile_used': 'demo',
            'region': 'us-east-1',
            'identities_analyzed': 25,
            'cloudtrail_included': True
        },
        'risk_scores': [
            # JSON-serializable risk score data
            {
                'identity_arn': 'arn:aws:iam::123456789012:user/admin-user',
                'total_score': 85.5,
                'risk_level': 'CRITICAL',
                'factor_scores': {}
            },
            {
                'identity_arn': 'arn:aws:iam::123456789012:user/dev-user',
                'total_score': 45.2,
                'risk_level': 'MEDIUM',
                'factor_scores': {}
            },
            {
                'identity_arn': 'arn:aws:iam::123456789012:role/service-role',
                'total_score': 72.1,
                'risk_level': 'HIGH',
                'factor_scores': {}
            }
        ],
        'summary_statistics': {
            'average_risk_score': 58.7,
            'risk_level_distribution': {
                'CRITICAL': 3,
                'HIGH': 8,
                'MEDIUM': 10,
                'LOW': 4
            },
            'total_identities': 25
        },
        'report_paths': {
            'html_dashboard': 'demo_reports/dashboard.html',
            'json_export': 'demo_reports/export.json',
            'csv_export': 'demo_reports/export.csv',
            'cli_summary': 'Demo CLI Summary',
            'executive_summary': 'Demo Executive Summary'
        },
        'raw_iam_data': {
            'AccountUsers': [],
            'AccountRoles': [],
            'AccountGroups': [],
            'AccountPolicies': []
        }
    }