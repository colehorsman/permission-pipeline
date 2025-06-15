#!/usr/bin/env python3
"""
Dashboard Visualizer - Text-based representation of the HTML dashboard

This script recreates the key visual elements of the HTML dashboard
in a text format that can be viewed in the terminal.
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def create_risk_level_chart(distribution):
    """Create a text-based pie chart for risk levels"""
    total = sum(distribution.values())
    if total == 0:
        return "No data available"
    
    chart = "\n📊 RISK LEVEL DISTRIBUTION\n"
    chart += "=" * 30 + "\n"
    
    levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    colors = ['🔴', '🟠', '🟡', '🟢']
    
    for level, color in zip(levels, colors):
        count = distribution.get(level, 0)
        percentage = (count / total) * 100
        bar_length = int(percentage / 5)  # Scale for display
        bar = "█" * bar_length + "░" * (20 - bar_length)
        
        chart += f"{color} {level:8} │{bar}│ {count:2d} ({percentage:4.1f}%)\n"
    
    return chart

def create_factor_bar_chart(factor_stats):
    """Create a text-based bar chart for risk factors"""
    chart = "\n📈 TOP RISK FACTORS (Average Scores)\n"
    chart += "=" * 40 + "\n"
    
    # Sort by average score
    sorted_factors = sorted(
        factor_stats.items(), 
        key=lambda x: x[1].get('average_score', 0), 
        reverse=True
    )
    
    for factor_name, stats in sorted_factors[:6]:  # Top 6
        clean_name = factor_name.replace('_', ' ').title()
        avg_score = stats.get('average_score', 0)
        high_risk_pct = stats.get('high_risk_percentage', 0)
        
        # Create visual bar
        bar_length = int(avg_score / 5)  # Scale to 20 chars max
        bar = "█" * bar_length + "░" * (20 - bar_length)
        
        # Color coding
        if avg_score >= 70:
            color = "🔴"
        elif avg_score >= 50:
            color = "🟠"
        elif avg_score >= 30:
            color = "🟡"
        else:
            color = "🟢"
        
        chart += f"{color} {clean_name[:20]:20} │{bar}│ {avg_score:5.1f} ({high_risk_pct:4.1f}% high risk)\n"
    
    return chart

def create_identity_table(top_scores):
    """Create a formatted table of top risky identities"""
    table = "\n🎯 TOP RISK IDENTITIES\n"
    table += "=" * 60 + "\n"
    table += f"{'Rank':<4} │ {'Identity Name':<25} │ {'Type':<4} │ {'Score':<5} │ {'Level':<8}\n"
    table += "─" * 60 + "\n"
    
    for i, score in enumerate(top_scores[:5], 1):
        risk_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(score.get('risk_level', 'LOW'), '⚪')
        
        name = score.get('name', 'Unknown')[:25]
        identity_type = score.get('type', 'UNK')
        risk_score = score.get('score', 0)
        risk_level = score.get('risk_level', 'LOW')
        
        table += f"{i:3d}  │ {name:<25} │ {identity_type:<4} │ {risk_score:5.1f} │ {risk_emoji} {risk_level}\n"
    
    return table

def create_detailed_analysis(scores):
    """Create detailed analysis of highest risk identity"""
    if not scores:
        return "No scores available for analysis"
    
    # Get highest risk identity
    highest_risk = max(scores, key=lambda x: x.overall_score)
    
    analysis = f"\n🔍 DETAILED ANALYSIS: {highest_risk.identity_name}\n"
    analysis += "=" * 50 + "\n"
    analysis += f"Overall Risk Score: {highest_risk.overall_score:.1f}/100 ({highest_risk.risk_level})\n\n"
    
    # Risk factor breakdown
    analysis += "RISK FACTOR BREAKDOWN:\n"
    analysis += "─" * 50 + "\n"
    
    # Sort factors by weighted impact
    sorted_factors = sorted(
        highest_risk.factor_scores.items(),
        key=lambda x: x[1].score * x[1].weight,
        reverse=True
    )
    
    for factor, score in sorted_factors[:5]:  # Top 5 factors
        factor_name = factor.value.replace('_', ' ').title()
        weighted_impact = score.score * score.weight
        
        # Visual indicator
        if score.score >= 80:
            indicator = "🔴 CRITICAL"
        elif score.score >= 60:
            indicator = "🟠 HIGH"
        elif score.score >= 40:
            indicator = "🟡 MEDIUM"
        else:
            indicator = "🟢 LOW"
        
        # Create mini bar
        bar_length = int(score.score / 10)
        mini_bar = "█" * bar_length + "░" * (10 - bar_length)
        
        analysis += f"\n{factor_name[:20]:20} │{mini_bar}│ {score.score:5.1f} {indicator}\n"
        analysis += f"{'':20} Weight: {score.weight:.2f} | Impact: {weighted_impact:.1f}\n"
        
        if score.details:
            analysis += f"{'':20} {score.details[:60]}...\n"
    
    # Recommendations
    analysis += f"\n💡 TOP RECOMMENDATIONS:\n"
    for i, rec in enumerate(highest_risk.recommendations[:3], 1):
        analysis += f"{i}. {rec[:70]}...\n"
    
    return analysis

def create_executive_summary(summary_stats):
    """Create executive summary dashboard"""
    total = summary_stats.get('total_identities', 0)
    avg_score = summary_stats.get('average_risk_score', 0)
    distribution = summary_stats.get('risk_level_distribution', {})
    
    critical_count = distribution.get('CRITICAL', 0)
    high_count = distribution.get('HIGH', 0)
    risk_count = critical_count + high_count
    risk_percentage = (risk_count / max(total, 1)) * 100
    
    # Determine overall assessment
    if avg_score >= 70:
        assessment = "🚨 SIGNIFICANT SECURITY RISK"
        urgency = "IMMEDIATE ACTION REQUIRED"
    elif avg_score >= 50:
        assessment = "⚠️  MODERATE SECURITY RISK"
        urgency = "ACTION RECOMMENDED WITHIN 1 WEEK"
    elif avg_score >= 30:
        assessment = "🟡 LOW-MODERATE RISK"
        urgency = "ROUTINE REVIEW AND IMPROVEMENT"
    else:
        assessment = "✅ GOOD SECURITY POSTURE"
        urgency = "CONTINUE MONITORING"
    
    summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  EXECUTIVE DASHBOARD                    ║
╚══════════════════════════════════════════════════════════════╝

📊 RISK OVERVIEW:
   Total IAM Identities: {total}
   Average Risk Score:   {avg_score:.1f}/100
   Assessment:          {assessment}
   
🚨 IMMEDIATE CONCERNS:
   Critical Risk:        {critical_count} identities
   High Risk:           {high_count} identities  
   Requiring Attention: {risk_count} identities ({risk_percentage:.1f}%)
   
⏰ URGENCY LEVEL:
   {urgency}
   
🎯 BUSINESS IMPACT:
   Security Risk:       {'HIGH' if avg_score >= 60 else 'MEDIUM' if avg_score >= 40 else 'LOW'}
   Compliance Risk:     {'HIGH' if risk_percentage > 20 else 'MEDIUM' if risk_percentage > 10 else 'LOW'}
   Operational Risk:    {'HIGH' if critical_count > 0 else 'MEDIUM' if high_count > 2 else 'LOW'}
"""
    
    return summary

def main():
    """Display the complete dashboard visualization"""
    # Load the demo data that was generated
    import json
    
    try:
        # Try to load the JSON report
        json_files = [f for f in os.listdir('demo_risk_reports') if f.endswith('.json')]
        if not json_files:
            print("❌ No demo reports found. Please run the risk scoring demo first:")
            print("   python3 examples/risk_scoring_demo.py")
            return 1
        
        json_file = os.path.join('demo_risk_reports', json_files[0])
        with open(json_file, 'r') as f:
            report_data = json.load(f)
        
        summary_stats = report_data['summary_statistics']
        identity_scores_data = report_data['identity_scores']
        
        # Convert to our expected format
        from airiam.analyzers.identity_risk_scorer import IdentityRiskScore, IdentityType, RiskFactor
        from datetime import datetime
        
        scores = []
        for score_data in identity_scores_data:
            # Create a mock score object for visualization
            class MockScore:
                def __init__(self, data):
                    self.identity_name = data['identity_name']
                    self.identity_type = IdentityType(data['identity_type'])
                    self.overall_score = data['overall_score']
                    self.risk_level = data['risk_level']
                    self.recommendations = data['recommendations']
                    
                    # Convert factor scores
                    self.factor_scores = {}
                    for factor_name, factor_data in data['factor_scores'].items():
                        try:
                            factor = RiskFactor(factor_name)
                            class MockFactorScore:
                                def __init__(self, fdata):
                                    self.score = fdata['score']
                                    self.weight = fdata['weight']
                                    self.details = fdata['details']
                            self.factor_scores[factor] = MockFactorScore(factor_data)
                        except ValueError:
                            continue  # Skip unknown factors
            
            scores.append(MockScore(score_data))
        
    except Exception as e:
        print(f"❌ Error loading demo data: {e}")
        print("Please run the risk scoring demo first:")
        print("   python3 examples/risk_scoring_demo.py")
        return 1
    
    # Display the complete dashboard
    print("\n" + "=" * 80)
    print("🚀 IAM RISK ASSESSMENT DASHBOARD - TEXT VISUALIZATION")
    print("=" * 80)
    
    # Executive Summary
    print(create_executive_summary(summary_stats))
    
    # Risk Level Distribution
    print(create_risk_level_chart(summary_stats['risk_level_distribution']))
    
    # Risk Factor Analysis
    print(create_factor_bar_chart(summary_stats['factor_statistics']))
    
    # Top Identities Table
    print(create_identity_table(summary_stats['top_risky_identities']))
    
    # Detailed Analysis
    print(create_detailed_analysis(scores))
    
    print("\n" + "=" * 80)
    print("✅ DASHBOARD VISUALIZATION COMPLETE!")
    print("📁 Full interactive reports available in: demo_risk_reports/")
    print("🌐 HTML Dashboard: Open iam_risk_dashboard_*.html in a browser")
    print("=" * 80)
    
    return 0

if __name__ == "__main__":
    exit(main())