"""
CSV Report Generator
Exports scan results to CSV format for spreadsheet analysis.
"""

import csv
from pathlib import Path
from typing import List
from datetime import datetime


class CSVReporter:
    """
    Generate CSV exports of scan results.
    
    Features:
    - Findings export (one row per finding)
    - Config issues export
    - Vulnerability export
    - Summary statistics
    """
    
    def generate_report(self, network_results: List, service_results: List,
                       mitre_findings: List, config_issues: List,
                       output_file: str):
        """
        Generate CSV report.
        
        Args:
            network_results: Network scan results
            service_results: Service enumeration results
            mitre_findings: MITRE mappings
            config_issues: Configuration issues
            output_file: Output CSV path
        """
        print(f"[*] Generating CSV report...")
        
        # Create directory
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Write findings to CSV
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = [
                'IP', 'Port', 'Service', 'Version', 'Risk Score', 'Risk Level',
                'MITRE Techniques', 'Config Issues', 'Vulnerabilities', 'Remediation'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in mitre_findings:
                # Determine risk level
                risk_level = 'Critical' if finding.risk_score >= 7.0 else \
                            'High' if finding.risk_score >= 5.0 else \
                            'Medium' if finding.risk_score >= 3.0 else 'Low'
                
                # Get MITRE techniques
                techniques = ', '.join([t.technique_id for t in finding.techniques])
                
                # Get config issues for this service
                service_config_issues = [
                    c.title for c in config_issues 
                    if c.ip == finding.ip and c.port == finding.port
                ]
                config_issues_str = '; '.join(service_config_issues) if service_config_issues else 'None'
                
                # Get vulnerabilities
                service_obj = next((s for s in service_results 
                                   if s.ip == finding.ip and s.port == finding.port), None)
                
                vulns_str = 'None'
                if service_obj and hasattr(service_obj, 'vulnerabilities') and service_obj.vulnerabilities:
                    vulns = [f"{v.cve_id} (CVSS: {v.cvss_score})" for v in service_obj.vulnerabilities[:3]]
                    vulns_str = '; '.join(vulns)
                
                # Remediation
                remediation = finding.rationale
                
                writer.writerow({
                    'IP': finding.ip,
                    'Port': finding.port,
                    'Service': finding.service,
                    'Version': finding.version or 'Unknown',
                    'Risk Score': finding.risk_score,
                    'Risk Level': risk_level,
                    'MITRE Techniques': techniques,
                    'Config Issues': config_issues_str,
                    'Vulnerabilities': vulns_str,
                    'Remediation': remediation
                })
        
        print(f"[+] CSV report saved to {output_file}")
    
    def generate_config_issues_csv(self, config_issues: List, output_file: str):
        """Generate separate CSV for configuration issues"""
        
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['IP', 'Port', 'Service', 'Severity', 'Issue Type', 
                         'Title', 'Description', 'Remediation']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for issue in config_issues:
                writer.writerow({
                    'IP': issue.ip,
                    'Port': issue.port,
                    'Service': issue.service,
                    'Severity': issue.severity,
                    'Issue Type': issue.issue_type,
                    'Title': issue.title,
                    'Description': issue.description,
                    'Remediation': issue.remediation
                })


def main():
    """Test CSV reporter"""
    print("CSV Reporter - Use through main.py pipeline")


if __name__ == '__main__':
    main()
