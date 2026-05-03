"""
Continuous Monitor Module
Tracks attack surface changes over time and alerts on critical modifications.
"""

import time
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class ScanSnapshot:
    """Represents a point-in-time snapshot of the attack surface"""
    timestamp: str
    target: str
    open_ports: Set[int]
    services: Dict[str, str]  # port -> service:version
    config_issues: int
    critical_issues: int
    high_issues: int
    vulnerabilities: int
    mitre_techniques: Set[str]
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'target': self.target,
            'open_ports': list(self.open_ports),
            'services': self.services,
            'config_issues': self.config_issues,
            'critical_issues': self.critical_issues,
            'high_issues': self.high_issues,
            'vulnerabilities': self.vulnerabilities,
            'mitre_techniques': list(self.mitre_techniques)
        }


@dataclass
class ChangeDetection:
    """Represents detected changes between scans"""
    timestamp: str
    change_type: str  # 'new_port', 'closed_port', 'new_service', 'new_vuln', 'config_change'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    description: str
    details: Dict
    
    def to_dict(self):
        return asdict(self)


class ContinuousMonitor:
    """
    Continuous monitoring system for attack surface changes.
    
    Features:
    - Periodic scanning at configurable intervals
    - Change detection and alerting
    - Historical trend tracking
    - Diff reports between scans
    - Configurable alert thresholds
    """
    
    HISTORY_DIR = "data/monitor_history"
    ALERTS_FILE = "data/monitor_alerts.json"
    
    def __init__(self, target: str, interval_minutes: int = 60, 
                 alert_on_new_ports: bool = True,
                 alert_on_new_vulns: bool = True):
        """
        Initialize continuous monitor.
        
        Args:
            target: Target to monitor (IP or CIDR)
            interval_minutes: Scan interval in minutes
            alert_on_new_ports: Alert when new ports are discovered
            alert_on_new_vulns: Alert when new vulnerabilities found
        """
        self.target = target
        self.interval_seconds = interval_minutes * 60
        self.alert_on_new_ports = alert_on_new_ports
        self.alert_on_new_vulns = alert_on_new_vulns
        
        # Create directories
        Path(self.HISTORY_DIR).mkdir(parents=True, exist_ok=True)
        
        # Load history
        self.snapshots: List[ScanSnapshot] = []
        self.alerts: List[ChangeDetection] = []
        self._load_history()
        
        self.running = False
    
    def _load_history(self):
        """Load historical snapshots"""
        try:
            history_file = f"{self.HISTORY_DIR}/{self._get_target_hash()}.json"
            if Path(history_file).exists():
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    
                for snapshot_data in data.get('snapshots', []):
                    snapshot = ScanSnapshot(
                        timestamp=snapshot_data['timestamp'],
                        target=snapshot_data['target'],
                        open_ports=set(snapshot_data['open_ports']),
                        services=snapshot_data['services'],
                        config_issues=snapshot_data['config_issues'],
                        critical_issues=snapshot_data['critical_issues'],
                        high_issues=snapshot_data['high_issues'],
                        vulnerabilities=snapshot_data['vulnerabilities'],
                        mitre_techniques=set(snapshot_data['mitre_techniques'])
                    )
                    self.snapshots.append(snapshot)
                
                print(f"[*] Loaded {len(self.snapshots)} historical snapshot(s)")
        
        except Exception as e:
            print(f"[!] Could not load history: {e}")
    
    def _save_history(self):
        """Save snapshot history to disk"""
        try:
            history_file = f"{self.HISTORY_DIR}/{self._get_target_hash()}.json"
            
            data = {
                'target': self.target,
                'snapshots': [s.to_dict() for s in self.snapshots[-100:]]  # Keep last 100
            }
            
            with open(history_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            print(f"[!] Could not save history: {e}")
    
    def _save_alert(self, change: ChangeDetection):
        """Save alert to disk"""
        try:
            alerts = []
            if Path(self.ALERTS_FILE).exists():
                with open(self.ALERTS_FILE, 'r') as f:
                    alerts = json.load(f)
            
            alerts.append(change.to_dict())
            
            # Keep last 1000 alerts
            alerts = alerts[-1000:]
            
            with open(self.ALERTS_FILE, 'w') as f:
                json.dump(alerts, f, indent=2)
        
        except Exception as e:
            print(f"[!] Could not save alert: {e}")
    
    def _get_target_hash(self) -> str:
        """Generate unique hash for target"""
        return hashlib.md5(self.target.encode()).hexdigest()[:12]
    
    def create_snapshot(self, scan_results, service_results, config_issues, mitre_findings) -> ScanSnapshot:
        """
        Create snapshot from scan results.
        
        Args:
            scan_results: Network scan results
            service_results: Service enumeration results
            config_issues: Configuration audit results
            mitre_findings: MITRE ATT&CK mappings
        
        Returns:
            ScanSnapshot object
        """
        # Extract open ports
        open_ports = set(r.port for r in scan_results)
        
        # Extract services (port -> service:version)
        services = {}
        for s in service_results:
            service_str = f"{s.service}"
            if s.version:
                service_str += f":{s.version}"
            services[str(s.port)] = service_str
        
        # Count vulnerabilities
        total_vulns = sum(len(s.vulnerabilities) for s in service_results 
                         if hasattr(s, 'vulnerabilities') and s.vulnerabilities)
        
        # Count config issues by severity
        critical_issues = len([c for c in config_issues if c.severity == 'CRITICAL'])
        high_issues = len([c for c in config_issues if c.severity == 'HIGH'])
        
        # Extract MITRE techniques
        mitre_techniques = set()
        for finding in mitre_findings:
            for tech in finding.techniques:
                mitre_techniques.add(tech.technique_id)
        
        snapshot = ScanSnapshot(
            timestamp=datetime.now().isoformat(),
            target=self.target,
            open_ports=open_ports,
            services=services,
            config_issues=len(config_issues),
            critical_issues=critical_issues,
            high_issues=high_issues,
            vulnerabilities=total_vulns,
            mitre_techniques=mitre_techniques
        )
        
        return snapshot
    
    def detect_changes(self, new_snapshot: ScanSnapshot) -> List[ChangeDetection]:
        """
        Compare new snapshot with previous to detect changes.
        
        Args:
            new_snapshot: Latest scan snapshot
        
        Returns:
            List of detected changes
        """
        changes = []
        
        if not self.snapshots:
            # First scan - no changes to detect
            return changes
        
        previous = self.snapshots[-1]
        
        # Detect new ports
        new_ports = new_snapshot.open_ports - previous.open_ports
        if new_ports and self.alert_on_new_ports:
            for port in new_ports:
                service = new_snapshot.services.get(str(port), 'Unknown')
                change = ChangeDetection(
                    timestamp=new_snapshot.timestamp,
                    change_type='new_port',
                    severity='HIGH',
                    description=f'New open port detected: {port}',
                    details={'port': port, 'service': service}
                )
                changes.append(change)
                print(f"[!] ALERT: New port {port} ({service}) detected")
        
        # Detect closed ports
        closed_ports = previous.open_ports - new_snapshot.open_ports
        if closed_ports:
            for port in closed_ports:
                service = previous.services.get(str(port), 'Unknown')
                change = ChangeDetection(
                    timestamp=new_snapshot.timestamp,
                    change_type='closed_port',
                    severity='MEDIUM',
                    description=f'Port closed: {port}',
                    details={'port': port, 'service': service}
                )
                changes.append(change)
                print(f"[*] INFO: Port {port} ({service}) closed")
        
        # Detect service changes
        for port in new_snapshot.open_ports.intersection(previous.open_ports):
            port_str = str(port)
            if port_str in new_snapshot.services and port_str in previous.services:
                if new_snapshot.services[port_str] != previous.services[port_str]:
                    change = ChangeDetection(
                        timestamp=new_snapshot.timestamp,
                        change_type='service_change',
                        severity='MEDIUM',
                        description=f'Service changed on port {port}',
                        details={
                            'port': port,
                            'old_service': previous.services[port_str],
                            'new_service': new_snapshot.services[port_str]
                        }
                    )
                    changes.append(change)
                    print(f"[!] ALERT: Service changed on port {port}: "
                          f"{previous.services[port_str]} → {new_snapshot.services[port_str]}")
        
        # Detect vulnerability increase
        if new_snapshot.vulnerabilities > previous.vulnerabilities and self.alert_on_new_vulns:
            vuln_increase = new_snapshot.vulnerabilities - previous.vulnerabilities
            change = ChangeDetection(
                timestamp=new_snapshot.timestamp,
                change_type='new_vulnerabilities',
                severity='CRITICAL',
                description=f'{vuln_increase} new vulnerabilities discovered',
                details={
                    'previous_count': previous.vulnerabilities,
                    'new_count': new_snapshot.vulnerabilities,
                    'increase': vuln_increase
                }
            )
            changes.append(change)
            print(f"[!] CRITICAL: {vuln_increase} new vulnerabilities detected!")
        
        # Detect critical issue increase
        if new_snapshot.critical_issues > previous.critical_issues:
            issue_increase = new_snapshot.critical_issues - previous.critical_issues
            change = ChangeDetection(
                timestamp=new_snapshot.timestamp,
                change_type='new_critical_issues',
                severity='CRITICAL',
                description=f'{issue_increase} new critical configuration issues',
                details={
                    'previous_count': previous.critical_issues,
                    'new_count': new_snapshot.critical_issues
                }
            )
            changes.append(change)
            print(f"[!] CRITICAL: {issue_increase} new critical config issues!")
        
        # Detect new MITRE techniques
        new_techniques = new_snapshot.mitre_techniques - previous.mitre_techniques
        if new_techniques:
            change = ChangeDetection(
                timestamp=new_snapshot.timestamp,
                change_type='new_attack_techniques',
                severity='HIGH',
                description=f'{len(new_techniques)} new attack techniques identified',
                details={'techniques': list(new_techniques)}
            )
            changes.append(change)
            print(f"[!] ALERT: {len(new_techniques)} new MITRE techniques: {', '.join(new_techniques)}")
        
        return changes
    
    def add_snapshot(self, snapshot: ScanSnapshot):
        """Add snapshot to history"""
        self.snapshots.append(snapshot)
        self._save_history()
    
    def process_scan_results(self, scan_results, service_results, config_issues, mitre_findings):
        """
        Process scan results and detect changes.
        
        Args:
            scan_results: Network scan results
            service_results: Service enumeration results
            config_issues: Configuration audit results
            mitre_findings: MITRE mappings
        """
        # Create snapshot
        snapshot = self.create_snapshot(scan_results, service_results, config_issues, mitre_findings)
        
        # Detect changes
        changes = self.detect_changes(snapshot)
        
        # Save alerts
        for change in changes:
            self.alerts.append(change)
            self._save_alert(change)
        
        # Add to history
        self.add_snapshot(snapshot)
        
        return changes
    
    def get_summary(self) -> Dict:
        """Get monitoring summary"""
        if not self.snapshots:
            return {
                'total_scans': 0,
                'monitoring_duration': '0 days',
                'total_alerts': 0
            }
        
        first_scan = datetime.fromisoformat(self.snapshots[0].timestamp)
        last_scan = datetime.fromisoformat(self.snapshots[-1].timestamp)
        duration = last_scan - first_scan
        
        # Alert breakdown
        alert_severity = {
            'critical': len([a for a in self.alerts if a.severity == 'CRITICAL']),
            'high': len([a for a in self.alerts if a.severity == 'HIGH']),
            'medium': len([a for a in self.alerts if a.severity == 'MEDIUM']),
            'low': len([a for a in self.alerts if a.severity == 'LOW'])
        }
        
        return {
            'target': self.target,
            'total_scans': len(self.snapshots),
            'first_scan': self.snapshots[0].timestamp,
            'last_scan': self.snapshots[-1].timestamp,
            'monitoring_duration': f"{duration.days} days, {duration.seconds // 3600} hours",
            'total_alerts': len(self.alerts),
            'alert_breakdown': alert_severity,
            'current_state': {
                'open_ports': len(self.snapshots[-1].open_ports),
                'services': len(self.snapshots[-1].services),
                'vulnerabilities': self.snapshots[-1].vulnerabilities,
                'critical_issues': self.snapshots[-1].critical_issues
            }
        }
    
    def generate_diff_report(self) -> str:
        """Generate text diff report between first and last scan"""
        if len(self.snapshots) < 2:
            return "Not enough data for diff report (need at least 2 scans)"
        
        first = self.snapshots[0]
        last = self.snapshots[-1]
        
        report = []
        report.append("=" * 70)
        report.append("ATTACK SURFACE CHANGE REPORT")
        report.append("=" * 70)
        report.append(f"Target: {self.target}")
        report.append(f"First Scan: {first.timestamp}")
        report.append(f"Last Scan: {last.timestamp}")
        report.append(f"Total Scans: {len(self.snapshots)}")
        report.append("")
        
        # Port changes
        new_ports = last.open_ports - first.open_ports
        closed_ports = first.open_ports - last.open_ports
        
        report.append("PORT CHANGES:")
        if new_ports:
            report.append(f"  ✅ New Open Ports ({len(new_ports)}): {sorted(new_ports)}")
        if closed_ports:
            report.append(f"  ❌ Closed Ports ({len(closed_ports)}): {sorted(closed_ports)}")
        if not new_ports and not closed_ports:
            report.append("  No port changes")
        report.append("")
        
        # Vulnerability trend
        report.append("VULNERABILITY TREND:")
        report.append(f"  Start: {first.vulnerabilities} CVEs")
        report.append(f"  Now: {last.vulnerabilities} CVEs")
        change = last.vulnerabilities - first.vulnerabilities
        if change > 0:
            report.append(f"  ⚠️  Increase: +{change} vulnerabilities")
        elif change < 0:
            report.append(f"  ✅ Decrease: {change} vulnerabilities")
        else:
            report.append(f"  No change")
        report.append("")
        
        # Config issues trend
        report.append("CONFIGURATION ISSUES:")
        report.append(f"  Start: {first.critical_issues} critical, {first.high_issues} high")
        report.append(f"  Now: {last.critical_issues} critical, {last.high_issues} high")
        report.append("")
        
        # Recent alerts
        recent_alerts = self.alerts[-10:]
        if recent_alerts:
            report.append("RECENT ALERTS (Last 10):")
            for alert in recent_alerts:
                report.append(f"  [{alert.severity}] {alert.description}")
        
        report.append("=" * 70)
        
        return "\n".join(report)


def main():
    """CLI for testing monitor"""
    print("Continuous Monitor - Use through main.py with --monitor flag")


if __name__ == '__main__':
    main()