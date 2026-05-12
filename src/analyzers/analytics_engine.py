"""
Analytics Engine
Advanced analytics for trend analysis and historical comparison.
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple
from collections import defaultdict
import statistics


class AnalyticsEngine:
    """
    Advanced analytics for security trends and patterns.
    
    Features:
    - Trend analysis over time
    - Risk distribution tracking
    - Compliance score evolution
    - Anomaly detection
    - Predictive insights
    """
    
    def __init__(self, history_dir: str = "data/analytics_history"):
        """Initialize analytics engine"""
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
    
    def record_scan(self, scan_data: Dict):
        """
        Record scan results for analytics.
        
        Args:
            scan_data: Dictionary with scan results
        """
        timestamp = datetime.now().isoformat()
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Store scan record
        record = {
            'scan_id': scan_id,
            'timestamp': timestamp,
            'target': scan_data.get('target'),
            'metrics': {
                'ports_open': scan_data.get('ports_open', 0),
                'services_found': scan_data.get('services_found', 0),
                'vulnerabilities': scan_data.get('vulnerabilities', 0),
                'critical_issues': scan_data.get('critical_issues', 0),
                'high_issues': scan_data.get('high_issues', 0),
                'medium_issues': scan_data.get('medium_issues', 0),
                'low_issues': scan_data.get('low_issues', 0),
                'compliance_score': scan_data.get('compliance_score', 100)
            }
        }
        
        # Append to history file
        history_file = self.history_dir / f"{scan_data.get('target', 'unknown').replace('/', '_')}.json"
        
        history = []
        if history_file.exists():
            with open(history_file, 'r') as f:
                history = json.load(f)
        
        history.append(record)
        
        # Keep last 100 records
        history = history[-100:]
        
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def get_trend_data(self, target: str, days: int = 30) -> Dict:
        """
        Get trend data for a target over specified days.
        
        Args:
            target: Target IP/hostname
            days: Number of days to analyze
        
        Returns:
            Dictionary with trend data
        """
        history_file = self.history_dir / f"{target.replace('/', '_')}.json"
        
        if not history_file.exists():
            return {'error': 'No historical data available'}
        
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        # Filter by date range
        cutoff_date = datetime.now() - timedelta(days=days)
        filtered = [
            record for record in history
            if datetime.fromisoformat(record['timestamp']) >= cutoff_date
        ]
        
        if not filtered:
            return {'error': 'No data in specified range'}
        
        # Extract trend data
        trends = {
            'timestamps': [r['timestamp'] for r in filtered],
            'ports_open': [r['metrics']['ports_open'] for r in filtered],
            'vulnerabilities': [r['metrics']['vulnerabilities'] for r in filtered],
            'critical_issues': [r['metrics']['critical_issues'] for r in filtered],
            'high_issues': [r['metrics']['high_issues'] for r in filtered],
            'compliance_score': [r['metrics']['compliance_score'] for r in filtered],
            'total_scans': len(filtered)
        }
        
        return trends
    
    def get_risk_heatmap(self, target: str) -> Dict:
        """
        Generate risk heat map data.
        
        Args:
            target: Target IP/hostname
        
        Returns:
            Heat map data
        """
        history_file = self.history_dir / f"{target.replace('/', '_')}.json"
        
        if not history_file.exists():
            return {'error': 'No historical data available'}
        
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        if not history:
            return {'error': 'No data available'}
        
        latest = history[-1]['metrics']
        
        # Calculate risk scores (0-10 scale)
        risk_map = {
            'network': min(10, latest['ports_open'] / 10),  # More ports = higher risk
            'vulnerabilities': min(10, latest['vulnerabilities'] * 2),
            'configuration': min(10, (latest['critical_issues'] * 3 + latest['high_issues'] * 2) / 5),
            'compliance': max(0, (100 - latest['compliance_score']) / 10)
        }
        
        return risk_map
    
    def get_statistics(self, target: str) -> Dict:
        """
        Calculate statistics for a target.
        
        Args:
            target: Target IP/hostname
        
        Returns:
            Statistical summary
        """
        history_file = self.history_dir / f"{target.replace('/', '_')}.json"
        
        if not history_file.exists():
            return {'error': 'No historical data available'}
        
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        if not history:
            return {'error': 'No data available'}
        
        # Extract metrics
        vulns = [r['metrics']['vulnerabilities'] for r in history]
        critical = [r['metrics']['critical_issues'] for r in history]
        compliance = [r['metrics']['compliance_score'] for r in history]
        
        stats = {
            'total_scans': len(history),
            'first_scan': history[0]['timestamp'],
            'last_scan': history[-1]['timestamp'],
            'vulnerabilities': {
                'current': vulns[-1],
                'average': round(statistics.mean(vulns), 2),
                'max': max(vulns),
                'min': min(vulns),
                'trend': 'increasing' if vulns[-1] > statistics.mean(vulns) else 'decreasing'
            },
            'critical_issues': {
                'current': critical[-1],
                'average': round(statistics.mean(critical), 2),
                'max': max(critical)
            },
            'compliance_score': {
                'current': compliance[-1],
                'average': round(statistics.mean(compliance), 2),
                'best': max(compliance),
                'worst': min(compliance),
                'trend': 'improving' if compliance[-1] > statistics.mean(compliance) else 'declining'
            }
        }
        
        return stats
    
    def detect_anomalies(self, target: str) -> List[Dict]:
        """
        Detect anomalies in scan data.
        
        Args:
            target: Target IP/hostname
        
        Returns:
            List of detected anomalies
        """
        history_file = self.history_dir / f"{target.replace('/', '_')}.json"
        
        if not history_file.exists():
            return []
        
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        if len(history) < 5:
            return []  # Need at least 5 scans for anomaly detection
        
        anomalies = []
        
        # Get recent metrics
        recent = history[-5:]
        latest = history[-1]['metrics']
        
        # Calculate averages from recent scans
        avg_vulns = statistics.mean([r['metrics']['vulnerabilities'] for r in recent[:-1]])
        avg_critical = statistics.mean([r['metrics']['critical_issues'] for r in recent[:-1]])
        avg_compliance = statistics.mean([r['metrics']['compliance_score'] for r in recent[:-1]])
        
        # Detect spikes
        if latest['vulnerabilities'] > avg_vulns * 1.5:
            anomalies.append({
                'type': 'vulnerability_spike',
                'severity': 'high',
                'message': f"Vulnerability count increased by {int((latest['vulnerabilities'] / avg_vulns - 1) * 100)}%",
                'current': latest['vulnerabilities'],
                'average': round(avg_vulns, 1)
            })
        
        if latest['critical_issues'] > avg_critical * 2:
            anomalies.append({
                'type': 'critical_issues_spike',
                'severity': 'critical',
                'message': f"Critical issues doubled from average",
                'current': latest['critical_issues'],
                'average': round(avg_critical, 1)
            })
        
        if latest['compliance_score'] < avg_compliance - 15:
            anomalies.append({
                'type': 'compliance_drop',
                'severity': 'high',
                'message': f"Compliance score dropped significantly",
                'current': latest['compliance_score'],
                'average': round(avg_compliance, 1)
            })
        
        return anomalies
    
    def get_comparison(self, target: str, scan_id_1: str, scan_id_2: str) -> Dict:
        """
        Compare two scans.
        
        Args:
            target: Target IP/hostname
            scan_id_1: First scan ID
            scan_id_2: Second scan ID
        
        Returns:
            Comparison data
        """
        history_file = self.history_dir / f"{target.replace('/', '_')}.json"
        
        if not history_file.exists():
            return {'error': 'No historical data available'}
        
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        scan1 = next((s for s in history if s['scan_id'] == scan_id_1), None)
        scan2 = next((s for s in history if s['scan_id'] == scan_id_2), None)
        
        if not scan1 or not scan2:
            return {'error': 'Scan(s) not found'}
        
        # Calculate differences
        comparison = {
            'scan_1': {
                'id': scan_id_1,
                'timestamp': scan1['timestamp'],
                'metrics': scan1['metrics']
            },
            'scan_2': {
                'id': scan_id_2,
                'timestamp': scan2['timestamp'],
                'metrics': scan2['metrics']
            },
            'changes': {
                'ports_open': scan2['metrics']['ports_open'] - scan1['metrics']['ports_open'],
                'vulnerabilities': scan2['metrics']['vulnerabilities'] - scan1['metrics']['vulnerabilities'],
                'critical_issues': scan2['metrics']['critical_issues'] - scan1['metrics']['critical_issues'],
                'compliance_score': scan2['metrics']['compliance_score'] - scan1['metrics']['compliance_score']
            }
        }
        
        return comparison


def main():
    """Test analytics engine"""
    print("Analytics Engine - Use through web UI or API")


if __name__ == '__main__':
    main()
