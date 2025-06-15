# IAM Identity Risk Scoring Guide

## Overview

The IAM Identity Risk Scorer provides comprehensive risk assessment for AWS IAM identities (users, roles, groups) using a 0-100 scoring scale with 10 different risk factors. This guide explains how to use the scoring system and interpret the results.

## 🎯 Risk Scoring System

### Risk Scale
- **0-39**: LOW risk - Good security posture
- **40-59**: MEDIUM risk - Some improvements needed  
- **60-79**: HIGH risk - Significant security concerns
- **80-100**: CRITICAL risk - Immediate action required

### Risk Factors

The scoring system evaluates 10 key risk factors with weighted importance:

| Risk Factor | Weight | Description |
|-------------|--------|-------------|
| **Policy Violations** | 20% | Security issues in attached policies |
| **Privilege Escalation** | 18% | Ability to increase own permissions |
| **Excessive Permissions** | 15% | Overly broad wildcard permissions |
| **Unused Access** | 12% | Services/permissions not being used |
| **Stale Credentials** | 10% | Old or unused access keys/passwords |
| **MFA Disabled** | 8% | Missing multi-factor authentication |
| **External Access** | 7% | Cross-account or public access |
| **Compliance Violations** | 5% | Violations of security frameworks |
| **Admin Access** | 3% | Administrative privileges |
| **Cross Account Access** | 2% | Ability to assume external roles |

## 🚀 Quick Start

### Basic Usage

```python
from airiam.analyzers.identity_risk_scorer import IdentityRiskScorer

# Initialize the scorer
scorer = IdentityRiskScorer()

# Score a single identity
risk_score = scorer.score_identity(identity_data)

print(f"Risk Score: {risk_score.overall_score:.1f}")
print(f"Risk Level: {risk_score.risk_level}")
```

### Batch Analysis

```python
# Score multiple identities
identities = [user1_data, role1_data, user2_data]
scores = scorer.score_multiple_identities(identities)

# Get summary statistics
summary = scorer.generate_risk_summary_report(scores)
print(f"Average Risk: {summary['average_risk_score']:.1f}")
```

## 📊 Risk Factor Deep Dive

### 1. Policy Violations (20% weight)
Analyzes attached and inline policies for security risks:
- Wildcard actions (`"Action": "*"`)
- Privilege escalation combinations
- Missing resource constraints
- Dangerous permissions without conditions

**Example High-Risk Policy:**
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

### 2. Privilege Escalation (18% weight)
Detects ability to increase permissions:
- `iam:CreateRole` + `iam:AttachRolePolicy`
- `iam:PassRole` without conditions
- `lambda:CreateFunction` with broad permissions
- `ec2:RunInstances` with unrestricted access

**Dangerous Actions:**
- `iam:CreateRole`, `iam:AttachRolePolicy`
- `iam:PutRolePolicy`, `iam:PassRole`
- `lambda:CreateFunction`, `lambda:UpdateFunctionCode`
- `ec2:RunInstances`, `ecs:RunTask`

### 3. Excessive Permissions (15% weight)
Identifies overly broad permissions:
- Wildcard actions and resources
- Ratio of wildcards to specific permissions
- Service-wide permissions when specific actions needed

### 4. Unused Access (12% weight)
Based on AWS Access Advisor data:
- Services granted but never used
- Time since last activity
- Unused services vs. total granted services

### 5. Stale Credentials (10% weight)
Evaluates credential freshness:
- Password age and last usage
- Access key age (>365 days = high risk)
- Account creation date

### 6. MFA Disabled (8% weight)
For users with console access:
- No MFA devices configured
- Inactive MFA devices
- Admin access without MFA

### 7. External Access (7% weight)
Cross-account access capabilities:
- AssumeRole policies allowing external accounts
- Public access principals
- Cross-account trust relationships

### 8. Compliance Violations (5% weight)
Framework-specific violations:
- **SOC2**: Admin access without MFA
- **PCI-DSS**: Wildcard permissions
- **GDPR**: Stale access beyond retention
- **NIST**: Weak password policies

### 9. Admin Access (3% weight)
Administrative privileges:
- AdministratorAccess policy
- Broad IAM permissions
- Account-level access

### 10. Cross Account Access (2% weight)
Ability to assume external roles:
- `sts:AssumeRole` permissions
- Cross-account role ARNs in policies

## 📋 Report Formats

### 1. Interactive HTML Dashboard
```python
from airiam.reporters.risk_score_reporter import RiskScoreReporter

reporter = RiskScoreReporter()
html_path = reporter.generate_html_dashboard(scores, summary_stats)
```

Features:
- Risk level distribution charts
- Top risky identities table
- Risk factor breakdown
- Interactive visualizations

### 2. JSON Export
```python
json_path = reporter.export_json_report(scores, summary_stats)
```

Perfect for:
- API integration
- Custom analysis tools
- Data pipeline integration

### 3. CSV Export
```python
csv_path = reporter.export_csv_report(scores)
```

Ideal for:
- Spreadsheet analysis
- Business reporting
- Historical tracking

### 4. CLI Summary
```python
summary_text = reporter.generate_cli_summary(scores, summary_stats)
print(summary_text)
```

## 🛠️ Advanced Usage

### Custom Risk Factor Weights

```python
from airiam.analyzers.identity_risk_scorer import RiskFactor

# Create security-focused weighting
security_weights = {
    RiskFactor.POLICY_VIOLATIONS: 0.25,
    RiskFactor.PRIVILEGE_ESCALATION: 0.25,
    RiskFactor.EXCESSIVE_PERMISSIONS: 0.20,
    # ... other factors
}

scorer = IdentityRiskScorer(custom_weights=security_weights)
```

### Integration with CloudTrail

```python
# Include CloudTrail data for better unused access analysis
cloudtrail_data = {
    "arn:aws:iam::123456789012:user/john": [
        # CloudTrail events for this user
    ]
}

scores = scorer.score_multiple_identities(identities, cloudtrail_data)
```

## 🎯 Interpreting Results

### Risk Score Ranges

**CRITICAL (80-100)**
- Immediate security threat
- Review within hours
- Likely compliance violations
- Potential for significant damage

**HIGH (60-79)**  
- Significant security concerns
- Review within 24-48 hours
- Multiple risk factors present
- Business risk exposure

**MEDIUM (40-59)**
- Moderate security issues
- Review within 1 week
- Some improvements needed
- Manageable risk level

**LOW (0-39)**
- Good security posture
- Routine monitoring sufficient
- Minor optimizations possible
- Acceptable risk level

### Sample Analysis

```
Identity: admin-user
Overall Score: 74.8 (HIGH)

Top Risk Factors:
• Privilege Escalation: 100.0 - Found 4 dangerous actions (3 unrestricted)
• Policy Violations: 80.0 - Found 5 policy violations (2 high severity)  
• Excessive Permissions: 75.0 - 1 wildcard actions, 2 wildcard resources

Recommendations:
1. Restrict privilege escalation actions with conditions
2. Review and remediate policy violations
3. Replace wildcard permissions with specific actions
```

## 🔧 Integration Examples

### With Existing AirIAM Analysis

```python
# Use with existing AirIAM workflow
from airiam.find_unused.find_unused import find_unused
from airiam.analyzers.identity_risk_scorer import IdentityRiskScorer

# Get IAM data from AirIAM
runtime_results = find_unused(logger, profile, no_cache, last_used_threshold, 'find_unused')
raw_data = runtime_results.get_raw_data()

# Score all users and roles
scorer = IdentityRiskScorer()
all_identities = raw_data['AccountUsers'] + raw_data['AccountRoles']
scores = scorer.score_multiple_identities(all_identities)

# Generate comprehensive report
reporter = RiskScoreReporter()
html_path = reporter.generate_html_dashboard(scores, 
    scorer.generate_risk_summary_report(scores))
```

### With CI/CD Pipeline

```python
def check_iam_risk_threshold(scores, max_allowed_score=60):
    """Fail CI/CD if any identity exceeds risk threshold"""
    high_risk_identities = [
        score for score in scores 
        if score.overall_score > max_allowed_score
    ]
    
    if high_risk_identities:
        print(f"❌ {len(high_risk_identities)} identities exceed risk threshold")
        for score in high_risk_identities:
            print(f"   {score.identity_name}: {score.overall_score:.1f}")
        return False
    
    return True
```

### With Security Hub Integration

```python
def send_to_security_hub(scores):
    """Send high-risk findings to AWS Security Hub"""
    for score in scores:
        if score.risk_level in ['CRITICAL', 'HIGH']:
            # Create Security Hub finding
            finding = {
                'Title': f'High-Risk IAM Identity: {score.identity_name}',
                'Description': f'Risk score: {score.overall_score:.1f}',
                'Severity': {'Label': score.risk_level}
            }
            # Send to Security Hub API
```

## 📈 Best Practices

### 1. Regular Assessment
- Run risk scoring weekly for critical environments
- Monthly for development environments
- Include in security review processes

### 2. Threshold Management
- Set organizational risk thresholds
- Automate alerts for threshold breaches
- Track risk score trends over time

### 3. Remediation Prioritization
```python
# Prioritize by weighted risk impact
def prioritize_remediation(scores):
    prioritized = []
    for score in scores:
        for factor, factor_score in score.factor_scores.items():
            if factor_score.score > 70:  # High individual factor score
                weighted_impact = factor_score.score * factor_score.weight
                prioritized.append({
                    'identity': score.identity_name,
                    'factor': factor.value,
                    'impact': weighted_impact,
                    'remediation': factor_score.remediation
                })
    
    return sorted(prioritized, key=lambda x: x['impact'], reverse=True)
```

### 4. Custom Weightings by Environment
```python
# Production environment - security focused
PROD_WEIGHTS = {
    RiskFactor.POLICY_VIOLATIONS: 0.30,
    RiskFactor.PRIVILEGE_ESCALATION: 0.25,
    RiskFactor.MFA_DISABLED: 0.15,
    # ...
}

# Development environment - flexibility focused  
DEV_WEIGHTS = {
    RiskFactor.UNUSED_ACCESS: 0.25,
    RiskFactor.STALE_CREDENTIALS: 0.20,
    RiskFactor.POLICY_VIOLATIONS: 0.15,
    # ...
}
```

## 🔍 Troubleshooting

### Common Issues

**No LastAccessed Data**
- Enable AWS Access Advisor
- Wait 24-48 hours for data collection
- Score will use 50 (medium) for unused access factor

**DateTime Parsing Errors**
- Ensure ISO 8601 format for dates
- Handle timezone differences properly
- Use string format: `"2024-06-14T10:30:00Z"`

**Missing Policy Documents**
- Ensure policy versions are included
- Check for inline vs. managed policies
- Verify policy document structure

### Performance Optimization

```python
# For large numbers of identities
import concurrent.futures

def score_identities_parallel(identities, max_workers=5):
    scorer = IdentityRiskScorer()
    scores = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_identity = {
            executor.submit(scorer.score_identity, identity): identity 
            for identity in identities
        }
        
        for future in concurrent.futures.as_completed(future_to_identity):
            try:
                score = future.result()
                scores.append(score)
            except Exception as e:
                print(f"Error scoring identity: {e}")
    
    return scores
```

## 📚 Examples

See `examples/risk_scoring_demo.py` for comprehensive usage examples including:
- Individual identity analysis
- Batch processing
- Report generation
- Custom weighting
- Integration patterns

Run the demo:
```bash
python3 examples/risk_scoring_demo.py
```

This will create sample reports in `demo_risk_reports/` directory.