"""
Risk Score Reporter and Visualization

This module provides comprehensive reporting and visualization capabilities
for IAM identity risk scores, including HTML dashboards, JSON exports,
and summary statistics.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from ..analyzers.identity_risk_scorer import IdentityRiskScore, RiskFactor


class RiskScoreReporter:
    """
    Generate comprehensive reports and visualizations for IAM identity risk scores.
    
    Supports multiple output formats:
    - Interactive HTML dashboard
    - JSON export for integration
    - CSV for spreadsheet analysis
    - Text summary for CLI output
    """

    def __init__(self, output_dir: str = "risk_reports"):
        """
        Initialize the risk score reporter
        
        Args:
            output_dir: Directory to save report files
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_html_dashboard(self, scores: List[IdentityRiskScore], 
                               summary_stats: Dict[str, Any]) -> str:
        """
        Generate an interactive HTML dashboard for risk scores
        
        Args:
            scores: List of identity risk scores
            summary_stats: Summary statistics from risk analysis
            
        Returns:
            Path to generated HTML file
        """
        html_content = self._build_html_dashboard(scores, summary_stats)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"iam_risk_dashboard_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath

    def _build_html_dashboard(self, scores: List[IdentityRiskScore], 
                             summary_stats: Dict[str, Any]) -> str:
        """Build the HTML dashboard content"""
        
        # Generate data for charts
        risk_level_data = self._generate_risk_level_chart_data(summary_stats)
        factor_data = self._generate_factor_chart_data(summary_stats)
        timeline_data = self._generate_timeline_data(scores)
        
        # Top risky identities table
        top_identities_table = self._generate_top_identities_table(scores[:10])
        
        # Risk factor breakdown
        factor_breakdown = self._generate_factor_breakdown_table(summary_stats)
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IAM Risk Assessment Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .dashboard-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .dashboard-card h3 {{
            margin-top: 0;
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        .metric {{
            text-align: center;
            padding: 20px;
        }}
        .metric-value {{
            font-size: 3em;
            font-weight: bold;
            margin: 0;
        }}
        .metric-label {{
            font-size: 1.1em;
            color: #666;
            margin: 5px 0;
        }}
        .critical {{ color: #e74c3c; }}
        .high {{ color: #f39c12; }}
        .medium {{ color: #f1c40f; }}
        .low {{ color: #27ae60; }}
        
        .risk-level-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .risk-level-critical {{
            background-color: #e74c3c;
            color: white;
        }}
        .risk-level-high {{
            background-color: #f39c12;
            color: white;
        }}
        .risk-level-medium {{
            background-color: #f1c40f;
            color: #333;
        }}
        .risk-level-low {{
            background-color: #27ae60;
            color: white;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
            margin-top: 20px;
        }}
        
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .recommendation-box {{
            background-color: #e8f5e8;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin: 10px 0;
        }}
        
        .alert-box {{
            background-color: #ffeaa7;
            border-left: 4px solid #fdcb6e;
            padding: 15px;
            margin: 10px 0;
        }}
        
        .critical-box {{
            background-color: #fab1a0;
            border-left: 4px solid #e17055;
            padding: 15px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ IAM Risk Assessment Dashboard</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Identities: {summary_stats.get('total_identities', 0)}</p>
    </div>

    <div class="summary-stats">
        <div class="dashboard-card metric">
            <div class="metric-value critical">{summary_stats.get('risk_level_distribution', {}).get('CRITICAL', 0)}</div>
            <div class="metric-label">Critical Risk</div>
        </div>
        <div class="dashboard-card metric">
            <div class="metric-value high">{summary_stats.get('risk_level_distribution', {}).get('HIGH', 0)}</div>
            <div class="metric-label">High Risk</div>
        </div>
        <div class="dashboard-card metric">
            <div class="metric-value medium">{summary_stats.get('risk_level_distribution', {}).get('MEDIUM', 0)}</div>
            <div class="metric-label">Medium Risk</div>
        </div>
        <div class="dashboard-card metric">
            <div class="metric-value">{summary_stats.get('average_risk_score', 0):.1f}</div>
            <div class="metric-label">Average Risk Score</div>
        </div>
    </div>

    <div class="dashboard-grid">
        <div class="dashboard-card">
            <h3>📊 Risk Level Distribution</h3>
            <div class="chart-container">
                <canvas id="riskLevelChart"></canvas>
            </div>
        </div>
        
        <div class="dashboard-card">
            <h3>⚠️ Risk Factor Analysis</h3>
            <div class="chart-container">
                <canvas id="riskFactorChart"></canvas>
            </div>
        </div>
    </div>

    <div class="dashboard-grid">
        <div class="dashboard-card">
            <h3>🎯 Top Risk Identities</h3>
            {top_identities_table}
        </div>
        
        <div class="dashboard-card">
            <h3>📈 Risk Factor Breakdown</h3>
            {factor_breakdown}
        </div>
    </div>

    <div class="dashboard-card">
        <h3>💡 Key Recommendations</h3>
        {self._generate_recommendations_section(scores, summary_stats)}
    </div>

    <script>
        // Risk Level Distribution Chart
        const riskLevelCtx = document.getElementById('riskLevelChart').getContext('2d');
        new Chart(riskLevelCtx, {{
            type: 'doughnut',
            data: {risk_level_data},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});

        // Risk Factor Chart
        const riskFactorCtx = document.getElementById('riskFactorChart').getContext('2d');
        new Chart(riskFactorCtx, {{
            type: 'bar',
            data: {factor_data},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        return html_template

    def _generate_risk_level_chart_data(self, summary_stats: Dict[str, Any]) -> str:
        """Generate Chart.js data for risk level distribution"""
        distribution = summary_stats.get('risk_level_distribution', {})
        
        data = {
            "labels": ["Critical", "High", "Medium", "Low"],
            "datasets": [{
                "data": [
                    distribution.get('CRITICAL', 0),
                    distribution.get('HIGH', 0),
                    distribution.get('MEDIUM', 0),
                    distribution.get('LOW', 0)
                ],
                "backgroundColor": [
                    "#e74c3c",  # Critical - Red
                    "#f39c12",  # High - Orange
                    "#f1c40f",  # Medium - Yellow
                    "#27ae60"   # Low - Green
                ],
                "borderWidth": 2,
                "borderColor": "#fff"
            }]
        }
        
        return json.dumps(data)

    def _generate_factor_chart_data(self, summary_stats: Dict[str, Any]) -> str:
        """Generate Chart.js data for risk factor analysis"""
        factor_stats = summary_stats.get('factor_statistics', {})
        
        labels = []
        scores = []
        colors = []
        
        for factor_name, stats in factor_stats.items():
            # Clean up factor names for display
            clean_name = factor_name.replace('_', ' ').title()
            labels.append(clean_name)
            scores.append(round(stats.get('average_score', 0), 1))
            
            # Color based on average score
            avg_score = stats.get('average_score', 0)
            if avg_score >= 70:
                colors.append('#e74c3c')  # Red
            elif avg_score >= 50:
                colors.append('#f39c12')  # Orange
            elif avg_score >= 30:
                colors.append('#f1c40f')  # Yellow
            else:
                colors.append('#27ae60')  # Green
        
        data = {
            "labels": labels,
            "datasets": [{
                "label": "Average Risk Score",
                "data": scores,
                "backgroundColor": colors,
                "borderColor": colors,
                "borderWidth": 1
            }]
        }
        
        return json.dumps(data)

    def _generate_timeline_data(self, scores: List[IdentityRiskScore]) -> str:
        """Generate timeline data for risk score trends"""
        # This would be more useful with historical data
        # For now, just return empty data
        return json.dumps({"labels": [], "datasets": []})

    def _generate_top_identities_table(self, top_scores: List[IdentityRiskScore]) -> str:
        """Generate HTML table for top risky identities"""
        if not top_scores:
            return "<p>No identities to display</p>"
        
        rows = []
        for score in top_scores:
            risk_class = f"risk-level-{score.risk_level.lower()}"
            rows.append(f"""
                <tr>
                    <td><strong>{score.identity_name}</strong></td>
                    <td>{score.identity_type.value}</td>
                    <td>{score.overall_score:.1f}</td>
                    <td><span class="risk-level-badge {risk_class}">{score.risk_level}</span></td>
                </tr>
            """)
        
        table_html = f"""
            <table>
                <thead>
                    <tr>
                        <th>Identity Name</th>
                        <th>Type</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        """
        
        return table_html

    def _generate_factor_breakdown_table(self, summary_stats: Dict[str, Any]) -> str:
        """Generate HTML table for risk factor breakdown"""
        factor_stats = summary_stats.get('factor_statistics', {})
        
        if not factor_stats:
            return "<p>No factor statistics available</p>"
        
        rows = []
        for factor_name, stats in factor_stats.items():
            clean_name = factor_name.replace('_', ' ').title()
            avg_score = stats.get('average_score', 0)
            high_risk_pct = stats.get('high_risk_percentage', 0)
            
            # Color code based on average score
            if avg_score >= 70:
                score_class = "critical"
            elif avg_score >= 50:
                score_class = "high"
            elif avg_score >= 30:
                score_class = "medium"
            else:
                score_class = "low"
            
            rows.append(f"""
                <tr>
                    <td>{clean_name}</td>
                    <td class="{score_class}"><strong>{avg_score:.1f}</strong></td>
                    <td>{high_risk_pct:.1f}%</td>
                </tr>
            """)
        
        table_html = f"""
            <table>
                <thead>
                    <tr>
                        <th>Risk Factor</th>
                        <th>Avg Score</th>
                        <th>High Risk %</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        """
        
        return table_html

    def _generate_recommendations_section(self, scores: List[IdentityRiskScore], 
                                        summary_stats: Dict[str, Any]) -> str:
        """Generate recommendations section HTML"""
        critical_count = summary_stats.get('risk_level_distribution', {}).get('CRITICAL', 0)
        high_count = summary_stats.get('risk_level_distribution', {}).get('HIGH', 0)
        
        recommendations = []
        
        if critical_count > 0:
            recommendations.append(f"""
                <div class="critical-box">
                    <strong>🚨 URGENT ACTION REQUIRED:</strong> {critical_count} identities have CRITICAL risk scores. 
                    Review and remediate immediately to prevent potential security incidents.
                </div>
            """)
        
        if high_count > 0:
            recommendations.append(f"""
                <div class="alert-box">
                    <strong>⚠️ HIGH PRIORITY:</strong> {high_count} identities have HIGH risk scores. 
                    Schedule remediation within 24-48 hours.
                </div>
            """)
        
        # Top factor recommendations
        factor_stats = summary_stats.get('factor_statistics', {})
        top_factors = sorted(
            factor_stats.items(), 
            key=lambda x: x[1].get('average_score', 0), 
            reverse=True
        )[:3]
        
        if top_factors:
            factor_recommendations = []
            for factor_name, stats in top_factors:
                clean_name = factor_name.replace('_', ' ').title()
                factor_recommendations.append(f"• {clean_name} (avg: {stats.get('average_score', 0):.1f})")
            
            recommendations.append(f"""
                <div class="recommendation-box">
                    <strong>💡 FOCUS AREAS:</strong> Address these top risk factors:
                    <br>{'<br>'.join(factor_recommendations)}
                </div>
            """)
        
        # General recommendations
        total_identities = summary_stats.get('total_identities', 0)
        avg_score = summary_stats.get('average_risk_score', 0)
        
        if avg_score > 60:
            recommendations.append(f"""
                <div class="alert-box">
                    <strong>📊 OVERALL ASSESSMENT:</strong> Average risk score of {avg_score:.1f} indicates 
                    significant security improvements needed across your IAM configuration.
                </div>
            """)
        elif avg_score > 40:
            recommendations.append(f"""
                <div class="recommendation-box">
                    <strong>📊 OVERALL ASSESSMENT:</strong> Average risk score of {avg_score:.1f} shows moderate risk. 
                    Focus on addressing high-risk identities and implementing least privilege principles.
                </div>
            """)
        else:
            recommendations.append(f"""
                <div class="recommendation-box">
                    <strong>✅ GOOD SECURITY POSTURE:</strong> Average risk score of {avg_score:.1f} indicates 
                    relatively good IAM security. Continue monitoring and addressing remaining issues.
                </div>
            """)
        
        return ''.join(recommendations)

    def export_json_report(self, scores: List[IdentityRiskScore], 
                          summary_stats: Dict[str, Any]) -> str:
        """
        Export risk scores to JSON format
        
        Args:
            scores: List of identity risk scores
            summary_stats: Summary statistics
            
        Returns:
            Path to generated JSON file
        """
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_identities': len(scores),
                'report_version': '1.0'
            },
            'summary_statistics': summary_stats,
            'identity_scores': [score.to_dict() for score in scores]
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"iam_risk_scores_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return filepath

    def export_csv_report(self, scores: List[IdentityRiskScore]) -> str:
        """
        Export risk scores to CSV format
        
        Args:
            scores: List of identity risk scores
            
        Returns:
            Path to generated CSV file
        """
        import csv
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"iam_risk_scores_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            header = [
                'Identity Name', 'Type', 'ARN', 'Overall Score', 'Risk Level',
                'Policy Violations', 'Privilege Escalation', 'Excessive Permissions',
                'Unused Access', 'Stale Credentials', 'MFA Disabled',
                'External Access', 'Compliance Violations', 'Admin Access',
                'Cross Account Access', 'Last Assessment', 'Top Recommendation'
            ]
            writer.writerow(header)
            
            # Data rows
            for score in scores:
                factor_scores = score.factor_scores
                row = [
                    score.identity_name,
                    score.identity_type.value,
                    score.identity_arn,
                    round(score.overall_score, 2),
                    score.risk_level,
                    round(factor_scores.get(RiskFactor.POLICY_VIOLATIONS, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.PRIVILEGE_ESCALATION, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.EXCESSIVE_PERMISSIONS, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.UNUSED_ACCESS, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.STALE_CREDENTIALS, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.MFA_DISABLED, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.EXTERNAL_ACCESS, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.COMPLIANCE_VIOLATIONS, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.ADMIN_ACCESS, type('obj', (object,), {'score': 0})).score, 2),
                    round(factor_scores.get(RiskFactor.CROSS_ACCOUNT_ACCESS, type('obj', (object,), {'score': 0})).score, 2),
                    score.last_assessment.isoformat(),
                    score.recommendations[0] if score.recommendations else ''
                ]
                writer.writerow(row)
        
        return filepath

    def generate_cli_summary(self, scores: List[IdentityRiskScore], 
                           summary_stats: Dict[str, Any]) -> str:
        """
        Generate a concise CLI-friendly summary
        
        Args:
            scores: List of identity risk scores
            summary_stats: Summary statistics
            
        Returns:
            Formatted summary string
        """
        if not scores:
            return "No identity risk scores to display."
        
        distribution = summary_stats.get('risk_level_distribution', {})
        
        summary = f"""
🛡️  IAM IDENTITY RISK ASSESSMENT SUMMARY
{'='*50}

📊 RISK DISTRIBUTION:
   Critical: {distribution.get('CRITICAL', 0):>3} identities
   High:     {distribution.get('HIGH', 0):>3} identities  
   Medium:   {distribution.get('MEDIUM', 0):>3} identities
   Low:      {distribution.get('LOW', 0):>3} identities
   
📈 STATISTICS:
   Total Identities:   {summary_stats.get('total_identities', 0)}
   Average Risk Score: {summary_stats.get('average_risk_score', 0):.1f}/100
   Highest Risk:       {summary_stats.get('highest_risk_score', 0):.1f}/100
   Lowest Risk:        {summary_stats.get('lowest_risk_score', 0):.1f}/100

🚨 TOP 5 HIGHEST RISK IDENTITIES:
"""
        
        for i, score in enumerate(scores[:5], 1):
            risk_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠', 
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(score.risk_level, '⚪')
            
            summary += f"   {i}. {score.identity_name} ({score.identity_type.value}) "
            summary += f"- {score.overall_score:.1f} {risk_emoji} {score.risk_level}\n"
        
        # Top risk factors
        factor_stats = summary_stats.get('factor_statistics', {})
        if factor_stats:
            top_factors = sorted(
                factor_stats.items(), 
                key=lambda x: x[1].get('average_score', 0), 
                reverse=True
            )[:3]
            
            summary += "\n⚠️  TOP RISK FACTORS:\n"
            for factor_name, stats in top_factors:
                clean_name = factor_name.replace('_', ' ').title()
                avg_score = stats.get('average_score', 0)
                high_risk_pct = stats.get('high_risk_percentage', 0)
                summary += f"   • {clean_name}: {avg_score:.1f} avg ({high_risk_pct:.1f}% high risk)\n"
        
        # Recommendations
        critical_count = distribution.get('CRITICAL', 0)
        high_count = distribution.get('HIGH', 0)
        
        summary += "\n💡 IMMEDIATE ACTIONS:\n"
        
        if critical_count > 0:
            summary += f"   🚨 URGENT: Review {critical_count} CRITICAL risk identities immediately\n"
        
        if high_count > 0:
            summary += f"   ⚠️  HIGH PRIORITY: Address {high_count} HIGH risk identities within 24h\n"
        
        if critical_count == 0 and high_count == 0:
            summary += "   ✅ No critical or high-risk identities found\n"
        
        summary += f"\n📁 Reports saved to: {self.output_dir}/\n"
        
        return summary

    def generate_executive_summary(self, summary_stats: Dict[str, Any]) -> str:
        """
        Generate an executive summary for leadership
        
        Args:
            summary_stats: Summary statistics
            
        Returns:
            Executive summary string
        """
        total = summary_stats.get('total_identities', 0)
        distribution = summary_stats.get('risk_level_distribution', {})
        avg_score = summary_stats.get('average_risk_score', 0)
        
        critical_pct = (distribution.get('CRITICAL', 0) / max(total, 1)) * 100
        high_pct = (distribution.get('HIGH', 0) / max(total, 1)) * 100
        risk_pct = critical_pct + high_pct
        
        if avg_score >= 70:
            overall_assessment = "SIGNIFICANT SECURITY RISK"
            urgency = "immediate action required"
        elif avg_score >= 50:
            overall_assessment = "MODERATE SECURITY RISK"
            urgency = "action recommended within 1 week"
        elif avg_score >= 30:
            overall_assessment = "LOW-MODERATE RISK"
            urgency = "routine review and improvement"
        else:
            overall_assessment = "GOOD SECURITY POSTURE"
            urgency = "continue monitoring"
        
        summary = f"""
EXECUTIVE SUMMARY - IAM SECURITY ASSESSMENT
{'='*60}

OVERALL ASSESSMENT: {overall_assessment}
Average Risk Score: {avg_score:.1f}/100

KEY FINDINGS:
• {total} IAM identities analyzed
• {risk_pct:.1f}% require immediate attention (Critical/High risk)
• {distribution.get('CRITICAL', 0)} identities pose critical security risks
• {distribution.get('HIGH', 0)} identities have high security risks

BUSINESS IMPACT:
• Security Risk Level: {'HIGH' if avg_score >= 60 else 'MEDIUM' if avg_score >= 40 else 'LOW'}
• Compliance Impact: {'HIGH' if risk_pct > 20 else 'MEDIUM' if risk_pct > 10 else 'LOW'}
• Operational Risk: {'HIGH' if critical_pct > 5 else 'MEDIUM' if critical_pct > 2 else 'LOW'}

RECOMMENDED ACTIONS:
Priority: {urgency.upper()}
1. Address all CRITICAL risk identities within 24 hours
2. Review HIGH risk identities within 1 week  
3. Implement least-privilege access controls
4. Enable comprehensive monitoring and alerting
5. Establish regular IAM review processes

ESTIMATED EFFORT: {'High (2-4 weeks)' if avg_score >= 60 else 'Medium (1-2 weeks)' if avg_score >= 40 else 'Low (few days)'}
"""
        
        return summary