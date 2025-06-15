"""
Executive Reporting Templates

This module provides executive-level reporting templates for IAM risk assessments,
including board presentations, compliance reports, and business impact analysis.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ExecutiveReportGenerator:
    """
    Generate executive-level reports for IAM risk assessments.
    
    Provides templates for:
    - Board presentations
    - Compliance status reports  
    - Business impact assessments
    - Risk trend analysis
    - Executive dashboards
    """

    def __init__(self):
        """Initialize the executive report generator"""
        pass

    def generate_board_presentation(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate a board-level presentation summary
        
        Args:
            analysis_results: Complete analysis results from AWS risk analyzer
            
        Returns:
            Formatted board presentation text
        """
        metadata = analysis_results.get('metadata', {})
        summary_stats = analysis_results.get('summary_statistics', {})
        
        account_id = metadata.get('account_id', 'Unknown')
        total_identities = metadata.get('identities_analyzed', 0)
        avg_score = summary_stats.get('average_risk_score', 0)
        distribution = summary_stats.get('risk_level_distribution', {})
        
        critical_count = distribution.get('CRITICAL', 0)
        high_count = distribution.get('HIGH', 0)
        risk_count = critical_count + high_count
        risk_percentage = (risk_count / max(total_identities, 1)) * 100
        
        # Determine overall risk posture
        if avg_score >= 70:
            risk_posture = "🔴 HIGH RISK"
            executive_action = "IMMEDIATE BOARD ATTENTION REQUIRED"
            timeline = "24-48 hours"
        elif avg_score >= 50:
            risk_posture = "🟠 ELEVATED RISK"
            executive_action = "EXECUTIVE OVERSIGHT RECOMMENDED"
            timeline = "1-2 weeks"
        elif avg_score >= 30:
            risk_posture = "🟡 MODERATE RISK"
            executive_action = "MANAGEMENT REVIEW REQUIRED"
            timeline = "1 month"
        else:
            risk_posture = "🟢 ACCEPTABLE RISK"
            executive_action = "CONTINUE MONITORING"
            timeline = "Quarterly review"
        
        # Business impact assessment
        if risk_percentage > 25:
            business_impact = "CRITICAL - Significant exposure to security incidents"
        elif risk_percentage > 15:
            business_impact = "HIGH - Notable security vulnerabilities present"
        elif risk_percentage > 5:
            business_impact = "MEDIUM - Some security improvements needed"
        else:
            business_impact = "LOW - Generally acceptable security posture"
        
        presentation = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          🛡️  BOARD CYBERSECURITY BRIEFING                    ║
║                              IAM Security Assessment                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 EXECUTIVE SUMMARY
   AWS Account: {account_id}
   Assessment Date: {metadata.get('analysis_date', datetime.now().strftime('%Y-%m-%d'))}
   
   Overall Security Posture: {risk_posture}
   Average Risk Score: {avg_score:.1f}/100
   
🎯 KEY FINDINGS
   Total IAM Identities: {total_identities:,}
   High-Risk Identities: {risk_count} ({risk_percentage:.1f}%)
   
   Risk Distribution:
   • Critical Risk: {critical_count:,} identities
   • High Risk: {high_count:,} identities
   • Medium Risk: {distribution.get('MEDIUM', 0):,} identities
   • Low Risk: {distribution.get('LOW', 0):,} identities

💼 BUSINESS IMPACT
   Risk Level: {business_impact}
   
   Potential Consequences:
   • Data breach exposure
   • Compliance violations
   • Operational disruption
   • Reputational damage
   
   Financial Impact Estimate:
   • Immediate remediation cost: ${self._estimate_remediation_cost(risk_count):,}
   • Potential breach cost: ${self._estimate_breach_cost(avg_score):,}

⏰ EXECUTIVE ACTION REQUIRED
   Priority: {executive_action}
   Timeline: {timeline}
   
   Board Oversight Needed:
   {'• Immediate risk review and approval of remediation plan' if avg_score >= 70 else ''}
   {'• Quarterly security updates to board' if avg_score >= 50 else ''}
   {'• Annual security posture review' if avg_score < 50 else ''}

🎯 STRATEGIC RECOMMENDATIONS
   1. Security Investment: {'Increase cybersecurity budget immediately' if avg_score >= 60 else 'Maintain current security investments'}
   2. Governance: {'Establish emergency security committee' if critical_count > 0 else 'Continue existing governance processes'}
   3. Compliance: {'Immediate compliance review required' if risk_percentage > 20 else 'Regular compliance monitoring sufficient'}
   4. Risk Management: {'Escalate to enterprise risk committee' if avg_score >= 70 else 'Include in standard risk reporting'}

📈 TREND ANALYSIS
   Current Risk Trajectory: {'Deteriorating' if avg_score >= 60 else 'Stable' if avg_score >= 40 else 'Improving'}
   
   Key Metrics to Monitor:
   • High-risk identity count (target: <5% of total)
   • Average risk score (target: <30)
   • Time to remediation (target: <48 hours for critical)
   • Repeat findings (target: <10%)

💡 NEXT STEPS
   Immediate (24-48 hours):
   • Executive briefing on critical findings
   • Resource allocation for remediation
   • Communication plan for stakeholders
   
   Short-term (1-4 weeks):
   • Implementation of security improvements
   • Enhanced monitoring and alerting
   • Staff training and awareness
   
   Long-term (1-6 months):
   • Security architecture review
   • Compliance framework updates
   • Third-party security assessment

────────────────────────────────────────────────────────────────────────────────
This assessment provides a snapshot of current IAM security posture.
Regular monitoring and continuous improvement are essential for maintaining
an acceptable risk level.

Report prepared by: AirIAM Security Assessment Platform
Next assessment due: {(datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d')}
════════════════════════════════════════════════════════════════════════════════"""
        
        return presentation

    def generate_compliance_report(self, analysis_results: Dict[str, Any], 
                                 frameworks: List[str] = None) -> str:
        """
        Generate compliance status report for specified frameworks
        
        Args:
            analysis_results: Complete analysis results
            frameworks: List of compliance frameworks to assess
            
        Returns:
            Formatted compliance report
        """
        if frameworks is None:
            frameworks = ['SOC2', 'PCI-DSS', 'HIPAA', 'GDPR', 'NIST']
        
        metadata = analysis_results.get('metadata', {})
        summary_stats = analysis_results.get('summary_statistics', {})
        scores = analysis_results.get('risk_scores', [])
        
        # Analyze compliance violations
        compliance_violations = self._analyze_compliance_violations(scores)
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                       📋 COMPLIANCE STATUS REPORT                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 ASSESSMENT OVERVIEW
   Account: {metadata.get('account_id', 'Unknown')}
   Date: {metadata.get('analysis_date', datetime.now().strftime('%Y-%m-%d'))}
   Identities Assessed: {len(scores):,}

🎯 COMPLIANCE FRAMEWORK STATUS
"""
        
        for framework in frameworks:
            status = self._assess_framework_compliance(framework, compliance_violations, summary_stats)
            report += f"""
   {framework}:
   Status: {status['status']}
   Violations: {status['violation_count']} findings
   Risk Level: {status['risk_level']}
   Remediation Priority: {status['priority']}
"""
        
        report += f"""
⚠️  CRITICAL COMPLIANCE GAPS
"""
        
        critical_gaps = self._identify_critical_compliance_gaps(compliance_violations)
        for gap in critical_gaps:
            report += f"   • {gap}\n"
        
        report += f"""
📈 COMPLIANCE METRICS
   Overall Compliance Score: {self._calculate_compliance_score(compliance_violations):.1f}%
   
   Framework Readiness:
   • Audit-Ready: {'Yes' if compliance_violations['total'] < 5 else 'No'}
   • Documentation Complete: {'Yes' if compliance_violations['policy_issues'] < 3 else 'No'}
   • Technical Controls: {'Yes' if compliance_violations['technical_issues'] < 5 else 'No'}

💡 REMEDIATION ROADMAP
   Priority 1 (Immediate): {compliance_violations['critical']} items
   Priority 2 (30 days): {compliance_violations['high']} items
   Priority 3 (90 days): {compliance_violations['medium']} items
   
   Estimated Effort: {self._estimate_compliance_effort(compliance_violations)} person-weeks
   Target Completion: {(datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d')}

📋 AUDIT PREPARATION
   Next Audit: TBD
   Documentation Required:
   • Updated IAM policies and procedures
   • Risk assessment reports
   • Remediation evidence
   • Control testing results

════════════════════════════════════════════════════════════════════════════════"""
        
        return report

    def generate_business_impact_assessment(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate business impact assessment focused on operational and financial implications
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            Formatted business impact assessment
        """
        metadata = analysis_results.get('metadata', {})
        summary_stats = analysis_results.get('summary_statistics', {})
        
        avg_score = summary_stats.get('average_risk_score', 0)
        distribution = summary_stats.get('risk_level_distribution', {})
        total_identities = metadata.get('identities_analyzed', 0)
        
        # Calculate business metrics
        downtime_risk = self._calculate_downtime_risk(avg_score, distribution)
        data_exposure_risk = self._calculate_data_exposure_risk(summary_stats)
        compliance_cost = self._estimate_compliance_cost(distribution)
        
        assessment = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      💼 BUSINESS IMPACT ASSESSMENT                           ║
║                           IAM Security Risks                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

🎯 EXECUTIVE SUMMARY
   Current Risk Level: {avg_score:.1f}/100
   Business Impact: {self._categorize_business_impact(avg_score)}
   
💰 FINANCIAL IMPACT ANALYSIS
   
   Direct Costs:
   • Immediate remediation: ${self._estimate_remediation_cost(distribution.get('CRITICAL', 0) + distribution.get('HIGH', 0)):,}
   • Compliance penalties (potential): ${compliance_cost:,}
   • Enhanced monitoring: ${25000:,} annually
   
   Risk-Adjusted Costs (potential):
   • Data breach: ${self._estimate_breach_cost(avg_score):,} (estimated)
   • Business interruption: ${downtime_risk:,} per incident
   • Reputation damage: ${self._estimate_reputation_cost(avg_score):,}
   
   Total Potential Exposure: ${self._estimate_breach_cost(avg_score) + downtime_risk + compliance_cost:,}

📊 OPERATIONAL IMPACT
   
   Service Availability:
   • Risk of unplanned downtime: {self._calculate_availability_risk(avg_score)}%
   • Mean time to resolution: {self._estimate_mttr(avg_score)} hours
   • Critical system exposure: {'High' if avg_score >= 60 else 'Medium' if avg_score >= 40 else 'Low'}
   
   Data Security:
   • Sensitive data at risk: {data_exposure_risk['data_at_risk']}%
   • Unauthorized access probability: {data_exposure_risk['access_probability']}%
   • Data classification compliance: {data_exposure_risk['classification_compliance']}%

🎯 BUSINESS CONTINUITY
   
   Recovery Objectives:
   • RTO (Recovery Time): {self._estimate_rto(avg_score)} hours
   • RPO (Recovery Point): {self._estimate_rpo(avg_score)} hours
   • Business impact duration: {self._estimate_impact_duration(avg_score)} days
   
   Critical Dependencies:
   • Customer-facing services: {'At risk' if avg_score >= 50 else 'Protected'}
   • Partner integrations: {'Vulnerable' if avg_score >= 60 else 'Secure'}
   • Regulatory reporting: {'Compromised' if avg_score >= 70 else 'Intact'}

📈 STRATEGIC IMPLICATIONS
   
   Competitive Position:
   • Customer trust impact: {self._assess_trust_impact(avg_score)}
   • Market positioning: {self._assess_market_impact(avg_score)}
   • Innovation capacity: {self._assess_innovation_impact(avg_score)}
   
   Growth Enablement:
   • M&A readiness: {'Poor' if avg_score >= 60 else 'Good' if avg_score <= 30 else 'Fair'}
   • Partner onboarding: {'Delayed' if avg_score >= 50 else 'Normal'}
   • Geographic expansion: {'Restricted' if avg_score >= 60 else 'Enabled'}

💡 RISK MITIGATION STRATEGY
   
   Immediate Actions (0-30 days):
   • Critical vulnerability remediation
   • Enhanced monitoring deployment
   • Incident response plan activation
   
   Short-term (1-6 months):
   • Security architecture improvements
   • Staff training and certification
   • Vendor security assessments
   
   Long-term (6-12 months):
   • Zero-trust architecture implementation
   • Advanced threat detection
   • Security culture transformation

📋 SUCCESS METRICS
   
   Target Objectives (12 months):
   • Risk score reduction to <30
   • Zero critical vulnerabilities
   • <5% high-risk identities
   • 99.9% availability maintained
   
   Business Outcomes:
   • Customer satisfaction maintained
   • Compliance costs reduced by 40%
   • Security incidents <2 per year
   • Audit readiness achieved

════════════════════════════════════════════════════════════════════════════════"""
        
        return assessment

    def generate_trend_analysis(self, historical_results: List[Dict[str, Any]]) -> str:
        """
        Generate trend analysis from historical assessment data
        
        Args:
            historical_results: List of historical analysis results
            
        Returns:
            Formatted trend analysis report
        """
        if len(historical_results) < 2:
            return "Insufficient historical data for trend analysis (minimum 2 assessments required)"
        
        # Sort by date
        sorted_results = sorted(historical_results, 
                               key=lambda x: x.get('metadata', {}).get('analysis_date', ''))
        
        current = sorted_results[-1]
        previous = sorted_results[-2]
        
        current_stats = current.get('summary_statistics', {})
        previous_stats = previous.get('summary_statistics', {})
        
        current_score = current_stats.get('average_risk_score', 0)
        previous_score = previous_stats.get('average_risk_score', 0)
        score_change = current_score - previous_score
        
        current_dist = current_stats.get('risk_level_distribution', {})
        previous_dist = previous_stats.get('risk_level_distribution', {})
        
        trend_direction = "📈 IMPROVING" if score_change < -5 else "📉 DETERIORATING" if score_change > 5 else "➡️  STABLE"
        
        analysis = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          📈 SECURITY TREND ANALYSIS                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 TREND OVERVIEW
   Analysis Period: {len(historical_results)} assessments
   Current Status: {trend_direction}
   
   Risk Score Trend:
   • Previous: {previous_score:.1f}
   • Current: {current_score:.1f}
   • Change: {score_change:+.1f} points
   
🎯 RISK DISTRIBUTION CHANGES
   
                    Previous    Current     Change
   Critical:        {previous_dist.get('CRITICAL', 0):>8}    {current_dist.get('CRITICAL', 0):>7}    {current_dist.get('CRITICAL', 0) - previous_dist.get('CRITICAL', 0):+3}
   High:            {previous_dist.get('HIGH', 0):>8}    {current_dist.get('HIGH', 0):>7}    {current_dist.get('HIGH', 0) - previous_dist.get('HIGH', 0):+3}
   Medium:          {previous_dist.get('MEDIUM', 0):>8}    {current_dist.get('MEDIUM', 0):>7}    {current_dist.get('MEDIUM', 0) - previous_dist.get('MEDIUM', 0):+3}
   Low:             {previous_dist.get('LOW', 0):>8}    {current_dist.get('LOW', 0):>7}    {current_dist.get('LOW', 0) - previous_dist.get('LOW', 0):+3}

📈 KEY PERFORMANCE INDICATORS
   
   Security Improvement Rate:
   • Target: -5 points per quarter
   • Actual: {score_change:.1f} points
   • Performance: {'✅ On track' if score_change <= -5 else '⚠️ Behind target' if score_change > 0 else '🟡 Slow progress'}
   
   Remediation Effectiveness:
   • Critical issues resolved: {max(0, previous_dist.get('CRITICAL', 0) - current_dist.get('CRITICAL', 0))}
   • High issues resolved: {max(0, previous_dist.get('HIGH', 0) - current_dist.get('HIGH', 0))}
   • New issues introduced: {max(0, current_dist.get('CRITICAL', 0) + current_dist.get('HIGH', 0) - previous_dist.get('CRITICAL', 0) - previous_dist.get('HIGH', 0))}

💡 PREDICTIVE ANALYSIS
   
   Projected 6-month outlook:
   • Risk score trajectory: {self._project_risk_trend(historical_results)}
   • Critical risk probability: {self._calculate_critical_probability(historical_results)}%
   • Compliance readiness: {self._project_compliance_readiness(historical_results)}

🎯 RECOMMENDATIONS
   
   Based on trend analysis:
   {'• Accelerate remediation efforts - risk increasing' if score_change > 5 else ''}
   {'• Maintain current security investments - stable trajectory' if -5 <= score_change <= 5 else ''}
   {'• Continue improvement program - positive trend' if score_change < -5 else ''}
   
   Focus Areas:
   • {self._identify_trend_focus_areas(historical_results)}

════════════════════════════════════════════════════════════════════════════════"""
        
        return analysis

    # Helper methods for calculations and assessments

    def _estimate_remediation_cost(self, high_risk_count: int) -> int:
        """Estimate cost to remediate high-risk findings"""
        return high_risk_count * 15000  # $15k per high-risk identity

    def _estimate_breach_cost(self, risk_score: float) -> int:
        """Estimate potential data breach cost based on risk score"""
        base_cost = 4_500_000  # Average breach cost
        risk_multiplier = risk_score / 100
        return int(base_cost * risk_multiplier)

    def _estimate_compliance_cost(self, distribution: Dict[str, int]) -> int:
        """Estimate potential compliance penalty costs"""
        critical = distribution.get('CRITICAL', 0)
        high = distribution.get('HIGH', 0)
        return (critical * 100000) + (high * 25000)

    def _calculate_downtime_risk(self, avg_score: float, distribution: Dict[str, int]) -> int:
        """Calculate potential business interruption cost"""
        downtime_hours = max(1, avg_score / 20)  # Hours of downtime
        hourly_cost = 50000  # $50k per hour
        return int(downtime_hours * hourly_cost)

    def _calculate_data_exposure_risk(self, summary_stats: Dict[str, Any]) -> Dict[str, float]:
        """Calculate data exposure risk metrics"""
        avg_score = summary_stats.get('average_risk_score', 0)
        return {
            'data_at_risk': min(avg_score * 1.2, 100),
            'access_probability': min(avg_score * 0.8, 100),
            'classification_compliance': max(100 - avg_score, 0)
        }

    def _categorize_business_impact(self, avg_score: float) -> str:
        """Categorize overall business impact"""
        if avg_score >= 70:
            return "🔴 SEVERE - Immediate threat to business operations"
        elif avg_score >= 50:
            return "🟠 HIGH - Significant operational risk"
        elif avg_score >= 30:
            return "🟡 MODERATE - Manageable risk with monitoring"
        else:
            return "🟢 LOW - Acceptable risk level"

    def _analyze_compliance_violations(self, scores: List[Any]) -> Dict[str, int]:
        """Analyze compliance violations across all scores"""
        violations = {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'policy_issues': 0,
            'technical_issues': 0
        }
        
        for score in scores:
            if hasattr(score, 'factor_scores'):
                for factor, factor_score in score.factor_scores.items():
                    if factor_score.score > 70:
                        violations['critical'] += 1
                    elif factor_score.score > 50:
                        violations['high'] += 1
                    elif factor_score.score > 30:
                        violations['medium'] += 1
                    
                    violations['total'] += 1
        
        return violations

    def _assess_framework_compliance(self, framework: str, violations: Dict[str, int], 
                                   summary_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance status for a specific framework"""
        avg_score = summary_stats.get('average_risk_score', 0)
        
        if avg_score >= 60:
            status = "🔴 NON-COMPLIANT"
            risk_level = "HIGH"
            priority = "IMMEDIATE"
        elif avg_score >= 40:
            status = "🟠 PARTIALLY COMPLIANT"
            risk_level = "MEDIUM"
            priority = "HIGH"
        else:
            status = "🟢 COMPLIANT"
            risk_level = "LOW"
            priority = "ROUTINE"
        
        return {
            'status': status,
            'violation_count': violations['total'],
            'risk_level': risk_level,
            'priority': priority
        }

    def _identify_critical_compliance_gaps(self, violations: Dict[str, int]) -> List[str]:
        """Identify critical compliance gaps"""
        gaps = []
        
        if violations['critical'] > 0:
            gaps.append(f"Critical security controls missing ({violations['critical']} findings)")
        
        if violations['policy_issues'] > 5:
            gaps.append("Policy documentation insufficient")
        
        if violations['technical_issues'] > 10:
            gaps.append("Technical control implementation inadequate")
        
        return gaps

    def _calculate_compliance_score(self, violations: Dict[str, int]) -> float:
        """Calculate overall compliance score"""
        total_possible = 100
        deductions = violations['critical'] * 10 + violations['high'] * 5 + violations['medium'] * 2
        return max(0, total_possible - deductions)

    def _estimate_compliance_effort(self, violations: Dict[str, int]) -> int:
        """Estimate effort required for compliance remediation"""
        return violations['critical'] * 2 + violations['high'] * 1 + violations['medium'] * 0.5

    # Additional helper methods would continue here...
    def _calculate_availability_risk(self, avg_score: float) -> float:
        """Calculate availability risk percentage"""
        return min(avg_score * 0.5, 50)

    def _estimate_mttr(self, avg_score: float) -> int:
        """Estimate mean time to resolution"""
        return max(4, int(avg_score / 10))

    def _estimate_rto(self, avg_score: float) -> int:
        """Estimate recovery time objective"""
        return max(1, int(avg_score / 20))

    def _estimate_rpo(self, avg_score: float) -> int:
        """Estimate recovery point objective"""
        return max(1, int(avg_score / 30))

    def _estimate_impact_duration(self, avg_score: float) -> int:
        """Estimate business impact duration"""
        return max(1, int(avg_score / 25))

    def _assess_trust_impact(self, avg_score: float) -> str:
        """Assess customer trust impact"""
        if avg_score >= 60:
            return "Significant erosion expected"
        elif avg_score >= 40:
            return "Moderate concern"
        else:
            return "Minimal impact"

    def _assess_market_impact(self, avg_score: float) -> str:
        """Assess market positioning impact"""
        if avg_score >= 60:
            return "Competitive disadvantage"
        elif avg_score >= 40:
            return "Neutral position"
        else:
            return "Competitive advantage"

    def _assess_innovation_impact(self, avg_score: float) -> str:
        """Assess innovation capacity impact"""
        if avg_score >= 60:
            return "Significantly constrained"
        elif avg_score >= 40:
            return "Moderately impacted"
        else:
            return "Unconstrained"

    def _estimate_reputation_cost(self, avg_score: float) -> int:
        """Estimate reputation damage cost"""
        base_cost = 2_000_000
        risk_factor = avg_score / 100
        return int(base_cost * risk_factor)

    def _project_risk_trend(self, historical_results: List[Dict[str, Any]]) -> str:
        """Project future risk trend"""
        if len(historical_results) < 3:
            return "Insufficient data for projection"
        
        # Simple linear projection
        scores = [r.get('summary_statistics', {}).get('average_risk_score', 0) for r in historical_results[-3:]]
        trend = (scores[-1] - scores[0]) / len(scores)
        
        if trend < -2:
            return "Continued improvement expected"
        elif trend > 2:
            return "Risk likely to increase"
        else:
            return "Stable trend expected"

    def _calculate_critical_probability(self, historical_results: List[Dict[str, Any]]) -> int:
        """Calculate probability of critical risk in next period"""
        # Simplified calculation based on trend
        recent_scores = [r.get('summary_statistics', {}).get('average_risk_score', 0) for r in historical_results[-2:]]
        avg_recent = sum(recent_scores) / len(recent_scores)
        
        return min(int(avg_recent * 1.5), 100)

    def _project_compliance_readiness(self, historical_results: List[Dict[str, Any]]) -> str:
        """Project compliance readiness"""
        recent_score = historical_results[-1].get('summary_statistics', {}).get('average_risk_score', 0)
        
        if recent_score <= 30:
            return "Audit-ready"
        elif recent_score <= 50:
            return "Minor gaps to address"
        else:
            return "Significant preparation needed"

    def _identify_trend_focus_areas(self, historical_results: List[Dict[str, Any]]) -> str:
        """Identify areas requiring focus based on trends"""
        # Simplified - would analyze factor trends in full implementation
        return "Policy violations, privilege escalation, unused access"