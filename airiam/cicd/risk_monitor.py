"""
CI/CD Risk Monitoring System

This module provides automated risk monitoring for continuous integration and deployment
pipelines, enabling proactive security alerting and policy enforcement.
"""

import json
import logging
import os
import subprocess
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict

from ..integrations.aws_risk_analyzer import AWSRiskAnalyzer
from ..tracking.improvement_tracker import SecurityImprovementTracker

logger = logging.getLogger(__name__)


@dataclass
class RiskThreshold:
    """Risk monitoring threshold configuration"""
    metric_name: str
    warning_threshold: float
    critical_threshold: float
    comparison: str  # 'greater_than', 'less_than', 'equals'
    enabled: bool = True


@dataclass
class MonitoringAlert:
    """Risk monitoring alert"""
    alert_id: str
    timestamp: datetime
    severity: str  # 'INFO', 'WARNING', 'CRITICAL'
    metric_name: str
    current_value: float
    threshold_value: float
    message: str
    account_id: str
    remediation_suggestions: List[str]


class CICDRiskMonitor:
    """
    Automated CI/CD risk monitoring system for continuous security assessment.
    
    Features:
    - Threshold-based alerting
    - Integration with CI/CD pipelines
    - Automated security gates
    - Slack/Teams notifications
    - Historical trend monitoring
    - Policy drift detection
    """

    def __init__(self, config_path: str = "cicd_monitor_config.yaml"):
        """
        Initialize CI/CD risk monitor
        
        Args:
            config_path: Path to monitoring configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.aws_analyzer = None
        self.tracker = SecurityImprovementTracker()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load monitoring configuration"""
        default_config = {
            'thresholds': [
                {
                    'metric_name': 'average_risk_score',
                    'warning_threshold': 40.0,
                    'critical_threshold': 60.0,
                    'comparison': 'greater_than',
                    'enabled': True
                },
                {
                    'metric_name': 'critical_count',
                    'warning_threshold': 1.0,
                    'critical_threshold': 3.0,
                    'comparison': 'greater_than',
                    'enabled': True
                },
                {
                    'metric_name': 'high_count',
                    'warning_threshold': 5.0,
                    'critical_threshold': 10.0,
                    'comparison': 'greater_than',
                    'enabled': True
                }
            ],
            'notifications': {
                'slack_webhook': os.getenv('SLACK_WEBHOOK_URL'),
                'email_recipients': os.getenv('ALERT_EMAIL_RECIPIENTS', '').split(','),
                'teams_webhook': os.getenv('TEAMS_WEBHOOK_URL')
            },
            'pipeline_integration': {
                'fail_on_critical': True,
                'fail_on_warning': False,
                'create_github_issue': True,
                'auto_remediation': False
            },
            'monitoring': {
                'check_interval_hours': 24,
                'retention_days': 90,
                'trend_analysis_days': 30
            }
        }
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        # Create default config file
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        return default_config

    def run_pipeline_check(self, aws_profile: Optional[str] = None,
                          fail_on_threshold: bool = True) -> Dict[str, Any]:
        """
        Run security check for CI/CD pipeline
        
        Args:
            aws_profile: AWS profile to use
            fail_on_threshold: Whether to fail pipeline on threshold breach
            
        Returns:
            Check results with pass/fail status
        """
        logger.info("Running CI/CD security pipeline check...")
        
        try:
            # Initialize AWS analyzer
            self.aws_analyzer = AWSRiskAnalyzer(profile=aws_profile)
            
            # Perform quick risk assessment
            quick_results = self.aws_analyzer.quick_risk_assessment()
            
            # Perform comprehensive analysis if needed
            if self.config['pipeline_integration'].get('comprehensive_analysis', False):
                analysis_results = self.aws_analyzer.analyze_account_risk(
                    include_cloudtrail=False,
                    output_dir="pipeline_risk_reports"
                )
            else:
                # Use quick results for faster pipeline execution
                analysis_results = {
                    'metadata': {
                        'account_id': quick_results['account_id'],
                        'analysis_date': quick_results['assessment_time'],
                        'identities_analyzed': quick_results['summary']['total_users'] + quick_results['summary']['total_roles']
                    },
                    'summary_statistics': {
                        'average_risk_score': self._calculate_quick_risk_score(quick_results),
                        'risk_level_distribution': {
                            'CRITICAL': len([f for f in quick_results['high_risk_findings'] if f['risk_level'] == 'CRITICAL']),
                            'HIGH': len([f for f in quick_results['high_risk_findings'] if f['risk_level'] == 'HIGH']),
                            'MEDIUM': 0,
                            'LOW': 0
                        }
                    }
                }
            
            # Check thresholds and generate alerts
            alerts = self._check_thresholds(analysis_results)
            
            # Determine pipeline status
            pipeline_status = self._determine_pipeline_status(alerts)
            
            # Record assessment
            assessment_id = self.tracker.record_assessment(analysis_results)
            
            # Send notifications if needed
            if alerts:
                self._send_notifications(alerts, analysis_results)
            
            # Create GitHub issue if configured
            if (alerts and 
                self.config['pipeline_integration'].get('create_github_issue', False) and 
                any(alert.severity in ['WARNING', 'CRITICAL'] for alert in alerts)):
                self._create_github_issue(alerts, analysis_results)
            
            results = {
                'pipeline_status': pipeline_status,
                'passed': pipeline_status == 'PASSED',
                'alerts': [asdict(alert) for alert in alerts],
                'assessment_id': assessment_id,
                'analysis_summary': analysis_results['summary_statistics'],
                'account_id': analysis_results['metadata']['account_id'],
                'check_timestamp': datetime.now().isoformat(),
                'remediation_required': len([a for a in alerts if a.severity == 'CRITICAL']) > 0
            }
            
            # Fail pipeline if configured and thresholds breached
            if (fail_on_threshold and 
                pipeline_status in ['FAILED_WARNING', 'FAILED_CRITICAL']):
                logger.error(f"Pipeline check failed: {pipeline_status}")
                if self.config['pipeline_integration'].get('fail_on_critical', True):
                    results['exit_code'] = 1
                elif (self.config['pipeline_integration'].get('fail_on_warning', False) and 
                      pipeline_status == 'FAILED_WARNING'):
                    results['exit_code'] = 1
                else:
                    results['exit_code'] = 0
            else:
                results['exit_code'] = 0
            
            logger.info(f"Pipeline check complete. Status: {pipeline_status}")
            return results
            
        except Exception as e:
            logger.error(f"Pipeline check failed: {e}")
            return {
                'pipeline_status': 'ERROR',
                'passed': False,
                'error': str(e),
                'exit_code': 1,
                'check_timestamp': datetime.now().isoformat()
            }

    def run_scheduled_monitoring(self, aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """
        Run scheduled monitoring check (for cron jobs, etc.)
        
        Args:
            aws_profile: AWS profile to use
            
        Returns:
            Monitoring results
        """
        logger.info("Running scheduled security monitoring...")
        
        try:
            # Initialize AWS analyzer
            self.aws_analyzer = AWSRiskAnalyzer(profile=aws_profile)
            
            # Perform comprehensive analysis
            analysis_results = self.aws_analyzer.analyze_account_risk(
                include_cloudtrail=True,
                output_dir=f"scheduled_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
            # Check thresholds
            alerts = self._check_thresholds(analysis_results)
            
            # Record assessment
            assessment_id = self.tracker.record_assessment(analysis_results)
            
            # Analyze trends
            trend_analysis = self.tracker.get_trend_analysis(
                days_back=self.config['monitoring']['trend_analysis_days']
            )
            
            # Send notifications for alerts
            if alerts:
                self._send_notifications(alerts, analysis_results, include_trends=True)
            
            # Auto-remediation if configured
            if (self.config['pipeline_integration'].get('auto_remediation', False) and
                any(alert.severity == 'CRITICAL' for alert in alerts)):
                remediation_results = self._attempt_auto_remediation(alerts, analysis_results)
            else:
                remediation_results = {'enabled': False}
            
            return {
                'monitoring_status': 'SUCCESS',
                'alerts_generated': len(alerts),
                'critical_alerts': len([a for a in alerts if a.severity == 'CRITICAL']),
                'assessment_id': assessment_id,
                'trend_analysis': trend_analysis,
                'remediation_results': remediation_results,
                'next_check': (datetime.now() + timedelta(
                    hours=self.config['monitoring']['check_interval_hours']
                )).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Scheduled monitoring failed: {e}")
            return {
                'monitoring_status': 'ERROR',
                'error': str(e),
                'next_check': (datetime.now() + timedelta(hours=1)).isoformat()
            }

    def _check_thresholds(self, analysis_results: Dict[str, Any]) -> List[MonitoringAlert]:
        """Check configured thresholds and generate alerts"""
        alerts = []
        summary_stats = analysis_results.get('summary_statistics', {})
        metadata = analysis_results.get('metadata', {})
        
        for threshold_config in self.config['thresholds']:
            if not threshold_config.get('enabled', True):
                continue
                
            threshold = RiskThreshold(**threshold_config)
            current_value = self._get_metric_value(threshold.metric_name, summary_stats)
            
            if current_value is None:
                continue
            
            # Check critical threshold
            if self._threshold_breached(current_value, threshold.critical_threshold, threshold.comparison):
                alert = MonitoringAlert(
                    alert_id=f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{threshold.metric_name}",
                    timestamp=datetime.now(),
                    severity='CRITICAL',
                    metric_name=threshold.metric_name,
                    current_value=current_value,
                    threshold_value=threshold.critical_threshold,
                    message=f"CRITICAL: {threshold.metric_name} ({current_value}) exceeds critical threshold ({threshold.critical_threshold})",
                    account_id=metadata.get('account_id', 'unknown'),
                    remediation_suggestions=self._get_remediation_suggestions(threshold.metric_name, 'CRITICAL')
                )
                alerts.append(alert)
                
            # Check warning threshold
            elif self._threshold_breached(current_value, threshold.warning_threshold, threshold.comparison):
                alert = MonitoringAlert(
                    alert_id=f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{threshold.metric_name}",
                    timestamp=datetime.now(),
                    severity='WARNING',
                    metric_name=threshold.metric_name,
                    current_value=current_value,
                    threshold_value=threshold.warning_threshold,
                    message=f"WARNING: {threshold.metric_name} ({current_value}) exceeds warning threshold ({threshold.warning_threshold})",
                    account_id=metadata.get('account_id', 'unknown'),
                    remediation_suggestions=self._get_remediation_suggestions(threshold.metric_name, 'WARNING')
                )
                alerts.append(alert)
        
        return alerts

    def _get_metric_value(self, metric_name: str, summary_stats: Dict[str, Any]) -> Optional[float]:
        """Extract metric value from summary statistics"""
        if metric_name == 'average_risk_score':
            return summary_stats.get('average_risk_score')
        elif metric_name == 'critical_count':
            return summary_stats.get('risk_level_distribution', {}).get('CRITICAL', 0)
        elif metric_name == 'high_count':
            return summary_stats.get('risk_level_distribution', {}).get('HIGH', 0)
        elif metric_name == 'total_identities':
            distribution = summary_stats.get('risk_level_distribution', {})
            return sum(distribution.values())
        return None

    def _threshold_breached(self, current_value: float, threshold: float, comparison: str) -> bool:
        """Check if threshold is breached"""
        if comparison == 'greater_than':
            return current_value > threshold
        elif comparison == 'less_than':
            return current_value < threshold
        elif comparison == 'equals':
            return current_value == threshold
        return False

    def _get_remediation_suggestions(self, metric_name: str, severity: str) -> List[str]:
        """Get remediation suggestions for specific metrics"""
        suggestions = {
            'average_risk_score': [
                "Review and remediate high-risk identities",
                "Implement least privilege access policies",
                "Enable MFA for all administrative accounts",
                "Remove unused access keys and permissions"
            ],
            'critical_count': [
                "Immediately review critical risk identities",
                "Disable or remediate admin accounts without MFA",
                "Remove excessive permissions from service accounts",
                "Implement emergency access procedures"
            ],
            'high_count': [
                "Prioritize remediation of high-risk identities",
                "Implement regular access reviews",
                "Update policies to follow least privilege",
                "Set up monitoring for privileged account usage"
            ]
        }
        
        return suggestions.get(metric_name, ["Review security configuration", "Consult security team"])

    def _determine_pipeline_status(self, alerts: List[MonitoringAlert]) -> str:
        """Determine overall pipeline status based on alerts"""
        if not alerts:
            return 'PASSED'
        
        critical_alerts = [a for a in alerts if a.severity == 'CRITICAL']
        warning_alerts = [a for a in alerts if a.severity == 'WARNING']
        
        if critical_alerts:
            return 'FAILED_CRITICAL'
        elif warning_alerts:
            return 'FAILED_WARNING'
        else:
            return 'PASSED'

    def _send_notifications(self, alerts: List[MonitoringAlert], 
                          analysis_results: Dict[str, Any],
                          include_trends: bool = False):
        """Send notifications for alerts"""
        if not alerts:
            return
        
        # Slack notification
        if self.config['notifications'].get('slack_webhook'):
            self._send_slack_notification(alerts, analysis_results, include_trends)
        
        # Teams notification
        if self.config['notifications'].get('teams_webhook'):
            self._send_teams_notification(alerts, analysis_results, include_trends)
        
        # Email notification
        email_recipients = self.config['notifications'].get('email_recipients', [])
        if email_recipients and email_recipients != ['']:
            self._send_email_notification(alerts, analysis_results, email_recipients, include_trends)

    def _send_slack_notification(self, alerts: List[MonitoringAlert], 
                               analysis_results: Dict[str, Any],
                               include_trends: bool = False):
        """Send Slack notification"""
        try:
            import requests
            
            webhook_url = self.config['notifications']['slack_webhook']
            if not webhook_url:
                return
            
            critical_count = len([a for a in alerts if a.severity == 'CRITICAL'])
            warning_count = len([a for a in alerts if a.severity == 'WARNING'])
            
            color = "danger" if critical_count > 0 else "warning"
            title = f"🚨 IAM Security Alert - {analysis_results['metadata']['account_id']}"
            
            fields = [
                {
                    "title": "Alert Summary",
                    "value": f"Critical: {critical_count}, Warnings: {warning_count}",
                    "short": True
                },
                {
                    "title": "Risk Score",
                    "value": f"{analysis_results['summary_statistics']['average_risk_score']:.1f}/100",
                    "short": True
                }
            ]
            
            # Add top alerts
            for alert in alerts[:3]:
                fields.append({
                    "title": f"{alert.severity}: {alert.metric_name}",
                    "value": alert.message,
                    "short": False
                })
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": title,
                    "fields": fields,
                    "footer": "AirIAM Security Monitor",
                    "ts": int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info("Slack notification sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

    def _create_github_issue(self, alerts: List[MonitoringAlert], 
                           analysis_results: Dict[str, Any]):
        """Create GitHub issue for security alerts"""
        try:
            # This would integrate with GitHub API
            # For now, create a simple issue template
            
            critical_alerts = [a for a in alerts if a.severity == 'CRITICAL']
            
            issue_title = f"Security Alert: {len(critical_alerts)} Critical IAM Issues Detected"
            
            issue_body = f"""
## 🚨 IAM Security Alert

**Account:** {analysis_results['metadata']['account_id']}
**Alert Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Risk Score:** {analysis_results['summary_statistics']['average_risk_score']:.1f}/100

### Critical Issues
"""
            
            for alert in critical_alerts:
                issue_body += f"""
#### {alert.metric_name}
- **Current Value:** {alert.current_value}
- **Threshold:** {alert.threshold_value}
- **Message:** {alert.message}

**Remediation Steps:**
"""
                for suggestion in alert.remediation_suggestions:
                    issue_body += f"- {suggestion}\n"
                
                issue_body += "\n"
            
            issue_body += """
### Next Steps
1. Review and remediate critical findings immediately
2. Update security policies and procedures
3. Schedule follow-up assessment

*This issue was automatically generated by AirIAM Security Monitor*
"""
            
            # Save issue template to file (could be posted via GitHub API)
            issue_file = f"security_issue_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(issue_file, 'w') as f:
                f.write(f"# {issue_title}\n\n{issue_body}")
            
            logger.info(f"GitHub issue template created: {issue_file}")
            
        except Exception as e:
            logger.error(f"Failed to create GitHub issue: {e}")

    def _calculate_quick_risk_score(self, quick_results: Dict[str, Any]) -> float:
        """Calculate risk score from quick assessment results"""
        findings = quick_results.get('high_risk_findings', [])
        summary = quick_results.get('summary', {})
        
        base_score = 20  # Base risk level
        
        # Add risk based on findings
        critical_findings = len([f for f in findings if f['risk_level'] == 'CRITICAL'])
        high_findings = len([f for f in findings if f['risk_level'] == 'HIGH'])
        
        risk_score = base_score + (critical_findings * 15) + (high_findings * 8)
        
        # Factor in admin users without MFA
        if summary.get('users_without_mfa', 0) > 0:
            risk_score += summary['users_without_mfa'] * 10
        
        # Factor in old access keys
        if summary.get('old_access_keys', 0) > 0:
            risk_score += summary['old_access_keys'] * 5
        
        return min(100.0, risk_score)

    def _attempt_auto_remediation(self, alerts: List[MonitoringAlert], 
                                analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt automated remediation of critical issues"""
        # This would implement automated fixes
        # For safety, this is disabled by default
        return {
            'enabled': True,
            'attempted_fixes': 0,
            'successful_fixes': 0,
            'message': 'Auto-remediation not implemented for safety'
        }

    def _send_teams_notification(self, alerts: List[MonitoringAlert], 
                               analysis_results: Dict[str, Any],
                               include_trends: bool = False):
        """Send Microsoft Teams notification"""
        # Implementation would be similar to Slack
        pass

    def _send_email_notification(self, alerts: List[MonitoringAlert], 
                               analysis_results: Dict[str, Any],
                               recipients: List[str],
                               include_trends: bool = False):
        """Send email notification"""
        # Implementation would use SMTP or email service
        pass

    def generate_monitoring_config(self, output_path: str = "cicd_monitor_config.yaml"):
        """Generate example monitoring configuration"""
        config = self._load_config()
        
        with open(output_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        logger.info(f"Monitoring configuration saved to: {output_path}")
        return output_path


def main():
    """CLI interface for CI/CD risk monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(description='CI/CD IAM Risk Monitoring')
    parser.add_argument('--mode', choices=['pipeline', 'scheduled', 'config'], 
                       default='pipeline', help='Monitoring mode')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--config', default='cicd_monitor_config.yaml', 
                       help='Configuration file path')
    parser.add_argument('--fail-on-threshold', action='store_true', 
                       help='Fail with non-zero exit code on threshold breach')
    
    args = parser.parse_args()
    
    try:
        monitor = CICDRiskMonitor(config_path=args.config)
        
        if args.mode == 'pipeline':
            print("🚀 Running CI/CD pipeline security check...")
            results = monitor.run_pipeline_check(
                aws_profile=args.profile,
                fail_on_threshold=args.fail_on_threshold
            )
            
            print(f"\n📊 PIPELINE CHECK RESULTS")
            print("=" * 50)
            print(f"Status: {'✅ PASSED' if results['passed'] else '❌ FAILED'}")
            print(f"Account: {results.get('account_id', 'Unknown')}")
            print(f"Risk Score: {results.get('analysis_summary', {}).get('average_risk_score', 0):.1f}/100")
            
            if results.get('alerts'):
                print(f"\n🚨 ALERTS ({len(results['alerts'])}):")
                for alert in results['alerts']:
                    print(f"   {alert['severity']}: {alert['message']}")
            
            return results.get('exit_code', 0)
            
        elif args.mode == 'scheduled':
            print("🕐 Running scheduled security monitoring...")
            results = monitor.run_scheduled_monitoring(aws_profile=args.profile)
            
            print(f"\n📊 MONITORING RESULTS")
            print("=" * 50)
            print(f"Status: {results['monitoring_status']}")
            print(f"Alerts Generated: {results.get('alerts_generated', 0)}")
            print(f"Critical Alerts: {results.get('critical_alerts', 0)}")
            print(f"Next Check: {results.get('next_check', 'Unknown')}")
            
            return 0
            
        elif args.mode == 'config':
            print("📝 Generating monitoring configuration...")
            config_path = monitor.generate_monitoring_config(args.config)
            print(f"Configuration saved to: {config_path}")
            return 0
            
    except Exception as e:
        print(f"❌ Monitoring failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())