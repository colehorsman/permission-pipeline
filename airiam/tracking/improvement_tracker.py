"""
Security Improvement Tracking System

This module provides comprehensive tracking of security improvements over time,
including trend analysis, goal setting, progress monitoring, and ROI calculation.
"""

import json
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SecurityGoal:
    """Represents a security improvement goal"""
    goal_id: str
    title: str
    description: str
    target_value: float
    current_value: float
    metric_type: str  # 'risk_score', 'identity_count', 'percentage'
    target_date: datetime
    status: str  # 'active', 'completed', 'overdue', 'cancelled'
    created_date: datetime
    priority: str  # 'critical', 'high', 'medium', 'low'
    category: str  # 'compliance', 'security', 'operational'


@dataclass
class ImprovementAction:
    """Represents a specific improvement action"""
    action_id: str
    title: str
    description: str
    identity_target: str  # ARN or name of target identity
    risk_factor: str  # Which risk factor this addresses
    status: str  # 'planned', 'in_progress', 'completed', 'failed'
    assigned_to: str
    created_date: datetime
    due_date: datetime
    completed_date: Optional[datetime]
    estimated_effort: float  # Hours
    actual_effort: Optional[float]
    impact_score: float  # Expected/actual risk reduction


@dataclass
class ProgressMetric:
    """Represents a progress measurement"""
    metric_id: str
    timestamp: datetime
    metric_name: str
    value: float
    account_id: str
    measurement_type: str  # 'automated', 'manual'
    notes: Optional[str]


class SecurityImprovementTracker:
    """
    Comprehensive security improvement tracking system.
    
    Features:
    - Historical trend analysis
    - Goal setting and tracking
    - Action item management
    - Progress visualization
    - ROI calculation
    - Automated progress detection
    """

    def __init__(self, db_path: str = "security_tracking.db"):
        """
        Initialize the security improvement tracker
        
        Args:
            db_path: Path to SQLite database for storing tracking data
        """
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Assessments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    total_identities INTEGER,
                    average_risk_score REAL,
                    critical_count INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    raw_data TEXT,
                    metadata TEXT
                )
            """)
            
            # Goals table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS goals (
                    goal_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    target_value REAL,
                    current_value REAL,
                    metric_type TEXT,
                    target_date TEXT,
                    status TEXT,
                    created_date TEXT,
                    priority TEXT,
                    category TEXT
                )
            """)
            
            # Actions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    identity_target TEXT,
                    risk_factor TEXT,
                    status TEXT,
                    assigned_to TEXT,
                    created_date TEXT,
                    due_date TEXT,
                    completed_date TEXT,
                    estimated_effort REAL,
                    actual_effort REAL,
                    impact_score REAL
                )
            """)
            
            # Metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    metric_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    metric_name TEXT,
                    value REAL,
                    account_id TEXT,
                    measurement_type TEXT,
                    notes TEXT
                )
            """)
            
            conn.commit()

    def record_assessment(self, analysis_results: Dict[str, Any]) -> str:
        """
        Record a new security assessment
        
        Args:
            analysis_results: Complete analysis results from risk analyzer
            
        Returns:
            Assessment ID
        """
        metadata = analysis_results.get('metadata', {})
        summary_stats = analysis_results.get('summary_statistics', {})
        
        assessment_id = f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            distribution = summary_stats.get('risk_level_distribution', {})
            
            cursor.execute("""
                INSERT INTO assessments (
                    timestamp, account_id, total_identities, average_risk_score,
                    critical_count, high_count, medium_count, low_count,
                    raw_data, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata.get('analysis_date', datetime.now().isoformat()),
                metadata.get('account_id', 'unknown'),
                metadata.get('identities_analyzed', 0),
                summary_stats.get('average_risk_score', 0),
                distribution.get('CRITICAL', 0),
                distribution.get('HIGH', 0),
                distribution.get('MEDIUM', 0),
                distribution.get('LOW', 0),
                json.dumps(analysis_results),
                json.dumps(metadata)
            ))
            
            conn.commit()
        
        # Auto-update goals and metrics
        self._update_progress_metrics(analysis_results)
        self._check_goal_progress()
        
        logger.info(f"Recorded assessment: {assessment_id}")
        return assessment_id

    def create_security_goal(self, title: str, description: str, target_value: float,
                           metric_type: str, target_date: datetime, priority: str = 'medium',
                           category: str = 'security') -> SecurityGoal:
        """
        Create a new security improvement goal
        
        Args:
            title: Goal title
            description: Detailed description
            target_value: Target value to achieve
            metric_type: Type of metric ('risk_score', 'identity_count', 'percentage')
            target_date: Target completion date
            priority: Goal priority
            category: Goal category
            
        Returns:
            Created SecurityGoal
        """
        import uuid
        goal_id = f"goal_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
        
        # Get current baseline value
        current_value = self._get_current_metric_value(metric_type)
        
        goal = SecurityGoal(
            goal_id=goal_id,
            title=title,
            description=description,
            target_value=target_value,
            current_value=current_value,
            metric_type=metric_type,
            target_date=target_date,
            status='active',
            created_date=datetime.now(),
            priority=priority,
            category=category
        )
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO goals (
                    goal_id, title, description, target_value, current_value,
                    metric_type, target_date, status, created_date, priority, category
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                goal.goal_id, goal.title, goal.description, goal.target_value,
                goal.current_value, goal.metric_type, goal.target_date.isoformat(),
                goal.status, goal.created_date.isoformat(), goal.priority, goal.category
            ))
            conn.commit()
        
        logger.info(f"Created security goal: {title}")
        return goal

    def create_improvement_action(self, title: str, description: str, identity_target: str,
                                risk_factor: str, assigned_to: str, due_date: datetime,
                                estimated_effort: float, impact_score: float) -> ImprovementAction:
        """
        Create a new improvement action
        
        Args:
            title: Action title
            description: Detailed description
            identity_target: Target identity ARN/name
            risk_factor: Risk factor being addressed
            assigned_to: Person/team assigned
            due_date: Due date
            estimated_effort: Estimated effort in hours
            impact_score: Expected risk reduction
            
        Returns:
            Created ImprovementAction
        """
        import uuid
        action_id = f"action_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
        
        action = ImprovementAction(
            action_id=action_id,
            title=title,
            description=description,
            identity_target=identity_target,
            risk_factor=risk_factor,
            status='planned',
            assigned_to=assigned_to,
            created_date=datetime.now(),
            due_date=due_date,
            completed_date=None,
            estimated_effort=estimated_effort,
            actual_effort=None,
            impact_score=impact_score
        )
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO actions (
                    action_id, title, description, identity_target, risk_factor,
                    status, assigned_to, created_date, due_date, completed_date,
                    estimated_effort, actual_effort, impact_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action.action_id, action.title, action.description, action.identity_target,
                action.risk_factor, action.status, action.assigned_to,
                action.created_date.isoformat(), action.due_date.isoformat(),
                None, action.estimated_effort, None, action.impact_score
            ))
            conn.commit()
        
        logger.info(f"Created improvement action: {title}")
        return action

    def update_action_status(self, action_id: str, status: str, 
                           actual_effort: Optional[float] = None,
                           notes: Optional[str] = None):
        """Update the status of an improvement action"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            completed_date = datetime.now().isoformat() if status == 'completed' else None
            
            cursor.execute("""
                UPDATE actions 
                SET status = ?, completed_date = ?, actual_effort = ?
                WHERE action_id = ?
            """, (status, completed_date, actual_effort, action_id))
            
            conn.commit()
        
        logger.info(f"Updated action {action_id} status to {status}")

    def get_trend_analysis(self, days_back: int = 90) -> Dict[str, Any]:
        """
        Get trend analysis for the specified time period
        
        Args:
            days_back: Number of days to analyze
            
        Returns:
            Trend analysis results
        """
        cutoff_date = datetime.now() - timedelta(days=days_back)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT timestamp, average_risk_score, critical_count, high_count,
                       medium_count, low_count, total_identities
                FROM assessments 
                WHERE timestamp >= ?
                ORDER BY timestamp
            """, (cutoff_date.isoformat(),))
            
            assessments = cursor.fetchall()
        
        if len(assessments) < 2:
            return {"error": "Insufficient data for trend analysis"}
        
        # Calculate trends
        first_assessment = assessments[0]
        last_assessment = assessments[-1]
        
        risk_score_change = last_assessment[1] - first_assessment[1]
        critical_change = last_assessment[2] - first_assessment[2]
        high_change = last_assessment[3] - first_assessment[3]
        
        # Determine trend direction
        if risk_score_change < -5:
            trend_direction = "IMPROVING"
            trend_emoji = "📈"
        elif risk_score_change > 5:
            trend_direction = "DETERIORATING"
            trend_emoji = "📉"
        else:
            trend_direction = "STABLE"
            trend_emoji = "➡️"
        
        return {
            "period_days": days_back,
            "assessments_count": len(assessments),
            "trend_direction": trend_direction,
            "trend_emoji": trend_emoji,
            "risk_score_change": risk_score_change,
            "critical_change": critical_change,
            "high_change": high_change,
            "first_score": first_assessment[1],
            "latest_score": last_assessment[1],
            "improvement_rate": risk_score_change / days_back if days_back > 0 else 0,
            "assessments": [
                {
                    "timestamp": a[0],
                    "risk_score": a[1],
                    "critical": a[2],
                    "high": a[3],
                    "medium": a[4],
                    "low": a[5],
                    "total": a[6]
                }
                for a in assessments
            ]
        }

    def get_goal_progress(self) -> List[Dict[str, Any]]:
        """Get progress on all active goals"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM goals WHERE status = 'active'
                ORDER BY priority DESC, target_date
            """)
            
            goals = cursor.fetchall()
        
        goal_progress = []
        for goal in goals:
            current_value = self._get_current_metric_value(goal[5])  # metric_type
            progress_percentage = self._calculate_goal_progress(goal[3], goal[4], current_value)  # target, initial, current
            
            days_remaining = (datetime.fromisoformat(goal[6]) - datetime.now()).days
            
            goal_progress.append({
                "goal_id": goal[0],
                "title": goal[1],
                "description": goal[2],
                "target_value": goal[3],
                "initial_value": goal[4],
                "current_value": current_value,
                "progress_percentage": progress_percentage,
                "days_remaining": days_remaining,
                "on_track": progress_percentage >= (100 - (days_remaining / 365 * 100)) if days_remaining > 0 else progress_percentage >= 100,
                "priority": goal[9],
                "category": goal[10]
            })
        
        return goal_progress

    def get_action_dashboard(self) -> Dict[str, Any]:
        """Get action item dashboard summary"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get action counts by status
            cursor.execute("""
                SELECT status, COUNT(*) FROM actions GROUP BY status
            """)
            status_counts = dict(cursor.fetchall())
            
            # Get overdue actions
            cursor.execute("""
                SELECT action_id, title, due_date, assigned_to, risk_factor
                FROM actions 
                WHERE status IN ('planned', 'in_progress') AND due_date < ?
                ORDER BY due_date
            """, (datetime.now().isoformat(),))
            overdue_actions = cursor.fetchall()
            
            # Get upcoming due actions (next 7 days)
            week_from_now = datetime.now() + timedelta(days=7)
            cursor.execute("""
                SELECT action_id, title, due_date, assigned_to, risk_factor
                FROM actions 
                WHERE status IN ('planned', 'in_progress') 
                AND due_date BETWEEN ? AND ?
                ORDER BY due_date
            """, (datetime.now().isoformat(), week_from_now.isoformat()))
            upcoming_actions = cursor.fetchall()
            
            # Calculate completion rate
            total_actions = sum(status_counts.values())
            completed_actions = status_counts.get('completed', 0)
            completion_rate = (completed_actions / total_actions * 100) if total_actions > 0 else 0
        
        return {
            "status_summary": status_counts,
            "completion_rate": completion_rate,
            "overdue_count": len(overdue_actions),
            "upcoming_count": len(upcoming_actions),
            "overdue_actions": [
                {
                    "action_id": a[0],
                    "title": a[1],
                    "due_date": a[2],
                    "assigned_to": a[3],
                    "risk_factor": a[4]
                }
                for a in overdue_actions
            ],
            "upcoming_actions": [
                {
                    "action_id": a[0],
                    "title": a[1],
                    "due_date": a[2],
                    "assigned_to": a[3],
                    "risk_factor": a[4]
                }
                for a in upcoming_actions
            ]
        }

    def calculate_roi(self, time_period_days: int = 365) -> Dict[str, Any]:
        """
        Calculate ROI of security improvements
        
        Args:
            time_period_days: Time period to analyze
            
        Returns:
            ROI analysis results
        """
        trend_analysis = self.get_trend_analysis(time_period_days)
        
        if "error" in trend_analysis:
            return {"error": "Insufficient data for ROI calculation"}
        
        # Calculate investment (estimated from completed actions)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cutoff_date = datetime.now() - timedelta(days=time_period_days)
            cursor.execute("""
                SELECT SUM(actual_effort), SUM(impact_score), COUNT(*)
                FROM actions 
                WHERE status = 'completed' AND completed_date >= ?
            """, (cutoff_date.isoformat(),))
            
            effort_data = cursor.fetchone()
        
        total_effort_hours = effort_data[0] or 0
        total_impact_score = effort_data[1] or 0
        completed_actions = effort_data[2] or 0
        
        # Calculate costs and benefits
        hourly_cost = 150  # Average security engineer cost
        investment_cost = total_effort_hours * hourly_cost
        
        # Risk reduction value
        risk_reduction = abs(trend_analysis.get("risk_score_change", 0))
        
        # Estimated value of risk reduction (based on potential breach cost avoidance)
        base_breach_cost = 4_500_000
        risk_reduction_value = base_breach_cost * (risk_reduction / 100)
        
        # Calculate ROI
        roi_percentage = ((risk_reduction_value - investment_cost) / investment_cost * 100) if investment_cost > 0 else 0
        
        return {
            "time_period_days": time_period_days,
            "investment_cost": investment_cost,
            "total_effort_hours": total_effort_hours,
            "completed_actions": completed_actions,
            "risk_reduction_percentage": risk_reduction,
            "estimated_value": risk_reduction_value,
            "roi_percentage": roi_percentage,
            "cost_per_risk_point": investment_cost / risk_reduction if risk_reduction > 0 else 0,
            "efficiency_score": total_impact_score / total_effort_hours if total_effort_hours > 0 else 0
        }

    def generate_progress_report(self) -> str:
        """Generate a comprehensive progress report"""
        trend = self.get_trend_analysis()
        goals = self.get_goal_progress()
        actions = self.get_action_dashboard()
        roi = self.calculate_roi()
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    📈 SECURITY IMPROVEMENT PROGRESS REPORT                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 TREND ANALYSIS (Last 90 Days)
   Overall Trend: {trend.get('trend_emoji', '❓')} {trend.get('trend_direction', 'UNKNOWN')}
   Risk Score Change: {trend.get('risk_score_change', 0):+.1f} points
   Improvement Rate: {trend.get('improvement_rate', 0):.2f} points/day
   
   Current Status:
   • Latest Risk Score: {trend.get('latest_score', 0):.1f}/100
   • Critical Identities: {trend.get('critical_change', 0):+d} change
   • High Risk Identities: {trend.get('high_change', 0):+d} change

🎯 GOAL PROGRESS
"""
        
        if goals:
            active_goals = len(goals)
            on_track_goals = len([g for g in goals if g['on_track']])
            
            report += f"   Active Goals: {active_goals}\n"
            report += f"   On Track: {on_track_goals} ({on_track_goals/active_goals*100:.1f}%)\n\n"
            
            for goal in goals[:3]:  # Show top 3
                progress_bar = "█" * int(goal['progress_percentage'] / 5) + "░" * (20 - int(goal['progress_percentage'] / 5))
                status_emoji = "✅" if goal['on_track'] else "⚠️"
                
                report += f"   {status_emoji} {goal['title']}\n"
                report += f"      Progress: │{progress_bar}│ {goal['progress_percentage']:.1f}%\n"
                report += f"      Target: {goal['target_value']:.1f} | Current: {goal['current_value']:.1f}\n"
                report += f"      Days Remaining: {max(0, goal['days_remaining'])}\n\n"
        else:
            report += "   No active goals set\n\n"
        
        report += f"""
📋 ACTION ITEMS
   Total Actions: {sum(actions['status_summary'].values())}
   Completion Rate: {actions['completion_rate']:.1f}%
   Overdue: {actions['overdue_count']} actions
   Due This Week: {actions['upcoming_count']} actions
   
   Status Breakdown:
   • Planned: {actions['status_summary'].get('planned', 0)}
   • In Progress: {actions['status_summary'].get('in_progress', 0)}
   • Completed: {actions['status_summary'].get('completed', 0)}
   • Failed: {actions['status_summary'].get('failed', 0)}

💰 RETURN ON INVESTMENT
   Investment: ${roi.get('investment_cost', 0):,.0f}
   Estimated Value: ${roi.get('estimated_value', 0):,.0f}
   ROI: {roi.get('roi_percentage', 0):+.1f}%
   
   Efficiency Metrics:
   • Cost per Risk Point: ${roi.get('cost_per_risk_point', 0):,.0f}
   • Effort Hours: {roi.get('total_effort_hours', 0):.1f}
   • Efficiency Score: {roi.get('efficiency_score', 0):.2f}

🚨 ATTENTION REQUIRED
"""
        
        if actions['overdue_count'] > 0:
            report += f"   {actions['overdue_count']} overdue actions need immediate attention:\n"
            for action in actions['overdue_actions'][:3]:
                report += f"   • {action['title']} (Due: {action['due_date'][:10]})\n"
        
        off_track_goals = [g for g in goals if not g['on_track']]
        if off_track_goals:
            report += f"\n   {len(off_track_goals)} goals are behind schedule:\n"
            for goal in off_track_goals[:3]:
                report += f"   • {goal['title']} ({goal['progress_percentage']:.1f}% complete)\n"
        
        if not actions['overdue_count'] and not off_track_goals:
            report += "   ✅ All items on track - excellent progress!\n"
        
        report += """
════════════════════════════════════════════════════════════════════════════════"""
        
        return report

    # Helper methods
    
    def _update_progress_metrics(self, analysis_results: Dict[str, Any]):
        """Update progress metrics from new assessment"""
        metadata = analysis_results.get('metadata', {})
        summary_stats = analysis_results.get('summary_statistics', {})
        
        metrics = [
            ('average_risk_score', summary_stats.get('average_risk_score', 0)),
            ('critical_count', summary_stats.get('risk_level_distribution', {}).get('CRITICAL', 0)),
            ('high_count', summary_stats.get('risk_level_distribution', {}).get('HIGH', 0)),
            ('total_identities', metadata.get('identities_analyzed', 0))
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for metric_name, value in metrics:
                metric_id = f"{metric_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                cursor.execute("""
                    INSERT INTO metrics (metric_id, timestamp, metric_name, value, account_id, measurement_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    metric_id, 
                    datetime.now().isoformat(),
                    metric_name,
                    value,
                    metadata.get('account_id', 'unknown'),
                    'automated'
                ))
            
            conn.commit()

    def _check_goal_progress(self):
        """Check and update goal progress based on latest metrics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM goals WHERE status = 'active'")
            goals = cursor.fetchall()
            
            for goal in goals:
                goal_id = goal[0]
                metric_type = goal[5]
                target_value = goal[3]
                target_date = datetime.fromisoformat(goal[6])
                
                current_value = self._get_current_metric_value(metric_type)
                
                # Update current value
                cursor.execute("""
                    UPDATE goals SET current_value = ? WHERE goal_id = ?
                """, (current_value, goal_id))
                
                # Check if goal is completed
                if self._is_goal_achieved(target_value, current_value, metric_type):
                    cursor.execute("""
                        UPDATE goals SET status = 'completed' WHERE goal_id = ?
                    """, (goal_id,))
                    logger.info(f"Goal {goal_id} completed!")
                
                # Check if goal is overdue
                elif datetime.now() > target_date:
                    cursor.execute("""
                        UPDATE goals SET status = 'overdue' WHERE goal_id = ?
                    """, (goal_id,))
            
            conn.commit()

    def _get_current_metric_value(self, metric_type: str) -> float:
        """Get the most recent value for a specific metric type"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if metric_type == 'risk_score':
                cursor.execute("""
                    SELECT average_risk_score FROM assessments 
                    ORDER BY timestamp DESC LIMIT 1
                """)
            elif metric_type == 'critical_count':
                cursor.execute("""
                    SELECT critical_count FROM assessments 
                    ORDER BY timestamp DESC LIMIT 1
                """)
            elif metric_type == 'high_count':
                cursor.execute("""
                    SELECT high_count FROM assessments 
                    ORDER BY timestamp DESC LIMIT 1
                """)
            else:
                return 0.0
            
            result = cursor.fetchone()
            return result[0] if result else 0.0

    def _calculate_goal_progress(self, target: float, initial: float, current: float) -> float:
        """Calculate progress percentage towards goal"""
        if initial == target:
            return 100.0
        
        progress = abs(current - initial) / abs(target - initial) * 100
        return min(100.0, progress)

    def _is_goal_achieved(self, target: float, current: float, metric_type: str) -> bool:
        """Check if a goal has been achieved"""
        if metric_type in ['risk_score']:
            return current <= target  # Lower is better
        else:
            return current <= target  # Assuming we want to reduce counts


def create_default_goals(tracker: SecurityImprovementTracker, 
                        current_risk_score: float) -> List[SecurityGoal]:
    """Create a set of default security improvement goals"""
    goals = []
    
    # Goal 1: Reduce overall risk score
    target_score = max(20, current_risk_score * 0.7)  # 30% improvement
    goal1 = tracker.create_security_goal(
        title="Reduce Overall Risk Score",
        description=f"Reduce average IAM risk score from {current_risk_score:.1f} to {target_score:.1f}",
        target_value=target_score,
        metric_type='risk_score',
        target_date=datetime.now() + timedelta(days=90),
        priority='high',
        category='security'
    )
    goals.append(goal1)
    
    # Goal 2: Eliminate critical risks
    goal2 = tracker.create_security_goal(
        title="Zero Critical Risk Identities",
        description="Eliminate all identities with critical risk levels",
        target_value=0,
        metric_type='critical_count',
        target_date=datetime.now() + timedelta(days=30),
        priority='critical',
        category='security'
    )
    goals.append(goal2)
    
    # Goal 3: Reduce high-risk identities
    goal3 = tracker.create_security_goal(
        title="Minimize High-Risk Identities",
        description="Reduce high-risk identities to less than 5% of total",
        target_value=5,  # 5% as target
        metric_type='percentage',
        target_date=datetime.now() + timedelta(days=60),
        priority='high',
        category='security'
    )
    goals.append(goal3)
    
    return goals