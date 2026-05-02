"""
HTML Report Generator
Creates interactive HTML reports with visualizations of attack surface findings.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict


class HTMLReporter:
    """
    Generate beautiful, interactive HTML reports for attack surface analysis.
    
    Features:
    - Executive summary dashboard
    - Risk distribution charts
    - MITRE ATT&CK technique breakdown
    - Configuration issue tracking
    - Detailed findings table
    - Responsive design
    """
    
    def __init__(self):
        self.report_data = {}
    
    def generate_report(self, network_results: List, service_results: List,
                       mitre_findings: List, config_issues: List = None, 
                       output_file: str = 'report.html'):
        """
        Generate complete HTML report.
        
        Args:
            network_results: List of ScanResult objects
            service_results: List of ServiceInfo objects
            mitre_findings: List of MappedFinding objects
            config_issues: List of ConfigIssue objects (optional)
            output_file: Output HTML file path
        """
        print(f"[*] Generating HTML report...")
        
        # Prepare data
        self.report_data = self._prepare_data(
            network_results, 
            service_results, 
            mitre_findings, 
            config_issues or []
        )
        
        # Generate HTML
        html_content = self._build_html()
        
        # Write to file
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to {output_file}")
    
    def _prepare_data(self, network_results, service_results, mitre_findings, config_issues) -> Dict:
        """Prepare data for HTML template"""
        
        # Calculate statistics
        total_hosts = len(set(r.ip for r in network_results))
        total_ports = len(network_results)
        total_services = len(service_results)
        
        # CVE statistics
        total_cves = 0
        critical_cves = 0
        high_cves = 0
        
        for service in service_results:
            if hasattr(service, 'vulnerabilities') and service.vulnerabilities:
                total_cves += len(service.vulnerabilities)
                for vuln in service.vulnerabilities:
                    if vuln.severity == 'CRITICAL':
                        critical_cves += 1
                    elif vuln.severity == 'HIGH':
                        high_cves += 1
        
        # MITRE statistics
        unique_techniques = set()
        all_tactics = set()
        
        for finding in mitre_findings:
            for tech in finding.techniques:
                unique_techniques.add(tech.technique_id)
                all_tactics.update(tech.tactics)
        
        # Risk distribution
        risk_critical = len([f for f in mitre_findings if f.risk_score >= 7.0])
        risk_high = len([f for f in mitre_findings if 5.0 <= f.risk_score < 7.0])
        risk_medium = len([f for f in mitre_findings if 3.0 <= f.risk_score < 5.0])
        risk_low = len([f for f in mitre_findings if f.risk_score < 3.0])
        
        # Configuration issues statistics
        config_critical = len([c for c in config_issues if c.severity == 'CRITICAL'])
        config_high = len([c for c in config_issues if c.severity == 'HIGH'])
        config_medium = len([c for c in config_issues if c.severity == 'MEDIUM'])
        config_low = len([c for c in config_issues if c.severity == 'LOW'])
        
        return {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_hosts': total_hosts,
            'total_ports': total_ports,
            'total_services': total_services,
            'total_cves': total_cves,
            'critical_cves': critical_cves,
            'high_cves': high_cves,
            'unique_techniques': len(unique_techniques),
            'total_tactics': len(all_tactics),
            'tactics_list': sorted(list(all_tactics)),
            'risk_critical': risk_critical,
            'risk_high': risk_high,
            'risk_medium': risk_medium,
            'risk_low': risk_low,
            'config_issues': config_issues,
            'total_config_issues': len(config_issues),
            'config_critical': config_critical,
            'config_high': config_high,
            'config_medium': config_medium,
            'config_low': config_low,
            'network_results': network_results,
            'service_results': service_results,
            'mitre_findings': sorted(mitre_findings, key=lambda x: x.risk_score, reverse=True)
        }
    
    def _build_html(self) -> str:
        """Build complete HTML report"""
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface Mapper - Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #0f0f23;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        
        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            color: white;
        }}
        
        .subtitle {{
            color: rgba(255,255,255,0.9);
            font-size: 1.1em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: #1a1a2e;
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        }}
        
        .stat-card.critical {{
            border-left-color: #e74c3c;
        }}
        
        .stat-card.high {{
            border-left-color: #e67e22;
        }}
        
        .stat-card.medium {{
            border-left-color: #f39c12;
        }}
        
        .stat-card.low {{
            border-left-color: #27ae60;
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        
        .stat-card.critical .stat-value {{
            color: #e74c3c;
        }}
        
        .stat-card.high .stat-value {{
            color: #e67e22;
        }}
        
        .stat-card.medium .stat-value {{
            color: #f39c12;
        }}
        
        .stat-card.low .stat-value {{
            color: #27ae60;
        }}
        
        .stat-label {{
            color: #a0a0a0;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .section {{
            background: #1a1a2e;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        }}
        
        h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        th {{
            background: #16213e;
            padding: 15px;
            text-align: left;
            color: #667eea;
            font-weight: 600;
            border-bottom: 2px solid #667eea;
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid #2a2a3e;
        }}
        
        tr:hover {{
            background: #16213e;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge-critical {{
            background: #e74c3c;
            color: white;
        }}
        
        .badge-high {{
            background: #e67e22;
            color: white;
        }}
        
        .badge-medium {{
            background: #f39c12;
            color: white;
        }}
        
        .badge-low {{
            background: #27ae60;
            color: white;
        }}
        
        .badge-open {{
            background: #3498db;
            color: white;
        }}
        
        .technique-tag {{
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 3px 10px;
            border-radius: 6px;
            margin: 2px;
            font-size: 0.85em;
        }}
        
        .tactic-pill {{
            display: inline-block;
            background: #764ba2;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            margin: 3px;
            font-size: 0.9em;
        }}
        
        .config-issue {{
            background: #16213e;
            padding: 15px;
            border-radius: 6px;
            margin: 10px 0;
            border-left: 4px solid #e74c3c;
        }}
        
        .issue-title {{
            color: #667eea;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        
        .issue-desc {{
            color: #a0a0a0;
            font-size: 0.95em;
            margin-bottom: 8px;
        }}
        
        .remediation {{
            background: #0f0f23;
            padding: 10px;
            border-radius: 4px;
            color: #27ae60;
            font-size: 0.9em;
            margin-top: 8px;
        }}
        
        footer {{
            text-align: center;
            color: #666;
            margin-top: 50px;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Attack Surface Mapper</h1>
            <div class="subtitle">Security Analysis Report - Generated {self.report_data['scan_time']}</div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{self.report_data['total_hosts']}</div>
                <div class="stat-label">Hosts Scanned</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-value">{self.report_data['total_ports']}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-value">{self.report_data['total_config_issues']}</div>
                <div class="stat-label">Config Issues</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-value">{self.report_data['total_cves']}</div>
                <div class="stat-label">CVEs Discovered</div>
            </div>
        </div>
        
        {self._build_config_issues_section()}
        {self._build_mitre_section()}
        {self._build_findings_table()}
        
        <footer>
            <p>Generated by Attack Surface Mapper | Built by Ahmed Dahdouh</p>
            <p>For authorized security testing only</p>
        </footer>
    </div>
</body>
</html>"""
    
    def _build_config_issues_section(self) -> str:
        """Build configuration issues section"""
        if not self.report_data['config_issues']:
            return ""
        
        issues_html = ""
        for issue in self.report_data['config_issues'][:10]:  # Top 10
            severity_class = issue.severity.lower()
            issues_html += f"""
            <div class="config-issue" style="border-left-color: {'#e74c3c' if issue.severity == 'CRITICAL' else '#e67e22' if issue.severity == 'HIGH' else '#f39c12' if issue.severity == 'MEDIUM' else '#27ae60'};">
                <div class="issue-title">
                    <span class="badge badge-{severity_class}">{issue.severity}</span>
                    {issue.title}
                </div>
                <div class="issue-desc">
                    <strong>{issue.ip}:{issue.port}</strong> - {issue.description}
                </div>
                <div class="remediation">
                    💡 Remediation: {issue.remediation}
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>⚙️ Configuration Issues ({self.report_data['total_config_issues']})</h2>
            <div style="margin-bottom: 20px;">
                <span class="badge badge-critical">Critical: {self.report_data['config_critical']}</span>
                <span class="badge badge-high">High: {self.report_data['config_high']}</span>
                <span class="badge badge-medium">Medium: {self.report_data['config_medium']}</span>
                <span class="badge badge-low">Low: {self.report_data['config_low']}</span>
            </div>
            {issues_html}
        </div>
        """
    
    def _build_mitre_section(self) -> str:
        """Build MITRE ATT&CK section"""
        tactics_html = ' '.join([f'<span class="tactic-pill">{t.replace("-", " ").title()}</span>' 
                                for t in self.report_data['tactics_list'][:10]])
        
        return f"""
        <div class="section">
            <h2>🎯 MITRE ATT&CK Coverage</h2>
            <p style="margin-bottom: 15px;">
                Identified <strong>{self.report_data['unique_techniques']}</strong> attack techniques 
                across <strong>{self.report_data['total_tactics']}</strong> tactics.
            </p>
            <div style="margin-top: 20px;">
                <strong>Tactics Covered:</strong><br>
                {tactics_html if tactics_html else '<span style="color: #666;">None</span>'}
            </div>
        </div>
        """
    
    def _build_findings_table(self) -> str:
        """Build findings table"""
        rows = ""
        
        for finding in self.report_data['mitre_findings'][:20]:  # Top 20
            risk_class = self._get_risk_class(finding.risk_score)
            techniques_html = ' '.join([f'<span class="technique-tag">{t.technique_id}</span>' 
                                       for t in finding.techniques[:3]])
            
            rows += f"""
            <tr>
                <td>{finding.ip}</td>
                <td>{finding.port}</td>
                <td>{finding.service}{' ' + finding.version if finding.version else ''}</td>
                <td><span class="badge badge-{risk_class}">{risk_class}</span></td>
                <td>{finding.risk_score}/10</td>
                <td>{techniques_html}</td>
            </tr>
            """
        
        return f"""
        <div class="section">
            <h2>🔍 Attack Surface Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Risk Level</th>
                        <th>Score</th>
                        <th>MITRE Techniques</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else '<tr><td colspan="6" style="text-align:center; color:#666;">No findings</td></tr>'}
                </tbody>
            </table>
        </div>
        """
    
    def _get_risk_class(self, score: float) -> str:
        """Convert risk score to CSS class"""
        if score >= 7.0:
            return 'critical'
        elif score >= 5.0:
            return 'high'
        elif score >= 3.0:
            return 'medium'
        else:
            return 'low'


def main():
    """Test HTML reporter"""
    print("HTML Reporter - Use through main.py pipeline")


if __name__ == '__main__':
    main()
