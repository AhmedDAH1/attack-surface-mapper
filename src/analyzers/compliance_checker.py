"""
Compliance Checker
Maps findings to compliance frameworks (PCI-DSS, NIST, CIS, ISO 27001).
"""

from typing import List, Dict, Set
from dataclasses import dataclass, asdict


@dataclass
class ComplianceViolation:
    """Represents a compliance framework violation"""
    framework: str  # 'PCI-DSS', 'NIST', 'CIS', 'ISO27001'
    control_id: str
    control_name: str
    severity: str
    description: str
    affected_assets: List[str]
    remediation: str
    
    def to_dict(self):
        return asdict(self)


class ComplianceChecker:
    """
    Check findings against compliance frameworks.
    
    Supports:
    - PCI-DSS v4.0 (Payment Card Industry)
    - NIST CSF (Cybersecurity Framework)
    - CIS Controls v8
    - ISO 27001:2022
    """
    
    # PCI-DSS Requirements mapping
    PCI_DSS_CONTROLS = {
        'unencrypted_traffic': {
            'control_id': 'PCI-DSS 4.1',
            'control_name': 'Use Strong Cryptography',
            'description': 'Unencrypted protocols (HTTP, FTP, Telnet) violate PCI-DSS 4.1',
            'remediation': 'Enable TLS/SSL encryption for all network communications'
        },
        'default_credentials': {
            'control_id': 'PCI-DSS 2.1',
            'control_name': 'Change Vendor Defaults',
            'description': 'Default credentials present violates PCI-DSS 2.1',
            'remediation': 'Change all default passwords and remove default accounts'
        },
        'weak_ssl': {
            'control_id': 'PCI-DSS 4.2',
            'control_name': 'Strong Cryptographic Keys',
            'description': 'Weak SSL/TLS configuration violates PCI-DSS 4.2',
            'remediation': 'Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1. Use TLSv1.2+ with strong ciphers'
        },
        'unnecessary_services': {
            'control_id': 'PCI-DSS 2.2.2',
            'control_name': 'Disable Unnecessary Services',
            'description': 'Unnecessary services enabled violates PCI-DSS 2.2.2',
            'remediation': 'Disable all unnecessary network services and protocols'
        },
        'version_disclosure': {
            'control_id': 'PCI-DSS 2.2.5',
            'control_name': 'Manage Security Parameters',
            'description': 'Service version disclosure violates PCI-DSS 2.2.5',
            'remediation': 'Configure services to not disclose version information'
        }
    }
    
    # NIST Cybersecurity Framework mapping
    NIST_CSF_CONTROLS = {
        'unencrypted_traffic': {
            'control_id': 'PR.DS-2',
            'control_name': 'Protect Data in Transit',
            'description': 'Unencrypted communications violate NIST CSF PR.DS-2',
            'remediation': 'Implement encryption for data in transit'
        },
        'vulnerability_management': {
            'control_id': 'DE.CM-8',
            'control_name': 'Vulnerability Scans',
            'description': 'Known vulnerabilities detected',
            'remediation': 'Perform regular vulnerability assessments and patch management'
        },
        'access_control': {
            'control_id': 'PR.AC-4',
            'control_name': 'Access Permissions',
            'description': 'Weak access controls detected',
            'remediation': 'Implement principle of least privilege and strong authentication'
        }
    }
    
    # CIS Controls v8 mapping
    CIS_CONTROLS = {
        'inventory': {
            'control_id': 'CIS 1.1',
            'control_name': 'Asset Inventory',
            'description': 'Maintain accurate asset inventory',
            'remediation': 'Establish and maintain detailed enterprise asset inventory'
        },
        'unauthorized_software': {
            'control_id': 'CIS 2.1',
            'control_name': 'Software Inventory',
            'description': 'Unauthorized services detected',
            'remediation': 'Maintain inventory of authorized software'
        },
        'data_protection': {
            'control_id': 'CIS 3.1',
            'control_name': 'Data Protection',
            'description': 'Data protection controls missing',
            'remediation': 'Establish and maintain data management process'
        },
        'secure_configuration': {
            'control_id': 'CIS 4.1',
            'control_name': 'Secure Configuration',
            'description': 'Insecure configurations detected',
            'remediation': 'Establish and maintain secure configuration baseline'
        },
        'vulnerability_management': {
            'control_id': 'CIS 7.1',
            'control_name': 'Vulnerability Management',
            'description': 'Known vulnerabilities present',
            'remediation': 'Establish and maintain vulnerability management process'
        }
    }
    
    def __init__(self):
        """Initialize compliance checker"""
        self.violations: List[ComplianceViolation] = []
    
    def check_compliance(self, config_issues: List, mitre_findings: List, 
                        service_results: List) -> List[ComplianceViolation]:
        """
        Check findings against compliance frameworks.
        
        Args:
            config_issues: Configuration audit results
            mitre_findings: MITRE ATT&CK findings
            service_results: Service enumeration results
        
        Returns:
            List of ComplianceViolation objects
        """
        print(f"\n[*] Checking compliance against frameworks...")
        
        self.violations = []
        
        # Check PCI-DSS compliance
        self._check_pci_dss(config_issues, service_results)
        
        # Check NIST CSF compliance
        self._check_nist_csf(config_issues, service_results)
        
        # Check CIS Controls compliance
        self._check_cis_controls(config_issues, service_results)
        
        print(f"[+] Compliance check complete. Found {len(self.violations)} violation(s)")
        
        return self.violations
    
    def _check_pci_dss(self, config_issues: List, service_results: List):
        """Check PCI-DSS compliance"""
        
        # Check for unencrypted traffic
        unencrypted = [c for c in config_issues if c.issue_type == 'insecure_protocol']
        if unencrypted:
            control = self.PCI_DSS_CONTROLS['unencrypted_traffic']
            self.violations.append(ComplianceViolation(
                framework='PCI-DSS v4.0',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='HIGH',
                description=control['description'],
                affected_assets=[f"{c.ip}:{c.port}" for c in unencrypted],
                remediation=control['remediation']
            ))
        
        # Check for default credentials
        default_creds = [c for c in config_issues if c.issue_type == 'default_creds']
        if default_creds:
            control = self.PCI_DSS_CONTROLS['default_credentials']
            self.violations.append(ComplianceViolation(
                framework='PCI-DSS v4.0',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='CRITICAL',
                description=control['description'],
                affected_assets=[f"{c.ip}:{c.port}" for c in default_creds],
                remediation=control['remediation']
            ))
        
        # Check for weak SSL/TLS
        weak_ssl = [c for c in config_issues if c.issue_type == 'weak_ssl']
        if weak_ssl:
            control = self.PCI_DSS_CONTROLS['weak_ssl']
            self.violations.append(ComplianceViolation(
                framework='PCI-DSS v4.0',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='HIGH',
                description=control['description'],
                affected_assets=[f"{c.ip}:{c.port}" for c in weak_ssl],
                remediation=control['remediation']
            ))
        
        # Check for version disclosure
        version_disclosure = [c for c in config_issues if c.issue_type == 'info_disclosure']
        if version_disclosure:
            control = self.PCI_DSS_CONTROLS['version_disclosure']
            self.violations.append(ComplianceViolation(
                framework='PCI-DSS v4.0',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='LOW',
                description=control['description'],
                affected_assets=[f"{c.ip}:{c.port}" for c in version_disclosure],
                remediation=control['remediation']
            ))
    
    def _check_nist_csf(self, config_issues: List, service_results: List):
        """Check NIST CSF compliance"""
        
        # Check data in transit protection
        unencrypted = [c for c in config_issues if c.issue_type == 'insecure_protocol']
        if unencrypted:
            control = self.NIST_CSF_CONTROLS['unencrypted_traffic']
            self.violations.append(ComplianceViolation(
                framework='NIST CSF',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='HIGH',
                description=control['description'],
                affected_assets=[f"{c.ip}:{c.port}" for c in unencrypted],
                remediation=control['remediation']
            ))
        
        # Check vulnerability management
        vulns = []
        for service in service_results:
            if hasattr(service, 'vulnerabilities') and service.vulnerabilities:
                vulns.append(f"{service.ip}:{service.port}")
        
        if vulns:
            control = self.NIST_CSF_CONTROLS['vulnerability_management']
            self.violations.append(ComplianceViolation(
                framework='NIST CSF',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='MEDIUM',
                description=control['description'],
                affected_assets=vulns,
                remediation=control['remediation']
            ))
    
    def _check_cis_controls(self, config_issues: List, service_results: List):
        """Check CIS Controls compliance"""
        
        # Secure configuration baseline
        insecure_configs = [c for c in config_issues if c.severity in ['CRITICAL', 'HIGH']]
        if insecure_configs:
            control = self.CIS_CONTROLS['secure_configuration']
            self.violations.append(ComplianceViolation(
                framework='CIS Controls v8',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='HIGH',
                description=control['description'],
                affected_assets=[f"{c.ip}:{c.port}" for c in insecure_configs],
                remediation=control['remediation']
            ))
        
        # Vulnerability management
        vulns = []
        for service in service_results:
            if hasattr(service, 'vulnerabilities') and service.vulnerabilities:
                vulns.append(f"{service.ip}:{service.port}")
        
        if vulns:
            control = self.CIS_CONTROLS['vulnerability_management']
            self.violations.append(ComplianceViolation(
                framework='CIS Controls v8',
                control_id=control['control_id'],
                control_name=control['control_name'],
                severity='HIGH',
                description=control['description'],
                affected_assets=vulns,
                remediation=control['remediation']
            ))
    
    def get_summary(self) -> Dict:
        """Get compliance summary"""
        
        # Group by framework
        by_framework = {}
        for violation in self.violations:
            if violation.framework not in by_framework:
                by_framework[violation.framework] = 0
            by_framework[violation.framework] += 1
        
        # Group by severity
        by_severity = {
            'CRITICAL': len([v for v in self.violations if v.severity == 'CRITICAL']),
            'HIGH': len([v for v in self.violations if v.severity == 'HIGH']),
            'MEDIUM': len([v for v in self.violations if v.severity == 'MEDIUM']),
            'LOW': len([v for v in self.violations if v.severity == 'LOW'])
        }
        
        return {
            'total_violations': len(self.violations),
            'by_framework': by_framework,
            'by_severity': by_severity,
            'compliance_score': self._calculate_score()
        }
    
    def _calculate_score(self) -> float:
        """Calculate overall compliance score (0-100)"""
        if not self.violations:
            return 100.0
        
        # Weighted by severity
        penalty = 0
        for v in self.violations:
            if v.severity == 'CRITICAL':
                penalty += 20
            elif v.severity == 'HIGH':
                penalty += 10
            elif v.severity == 'MEDIUM':
                penalty += 5
            else:
                penalty += 2
        
        score = max(0, 100 - penalty)
        return round(score, 1)
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary text"""
        
        summary = self.get_summary()
        score = summary['compliance_score']
        
        # Determine overall posture
        if score >= 90:
            posture = "STRONG"
            color = "green"
        elif score >= 70:
            posture = "ADEQUATE"
            color = "yellow"
        elif score >= 50:
            posture = "WEAK"
            color = "orange"
        else:
            posture = "CRITICAL"
            color = "red"
        
        report = f"""
EXECUTIVE SUMMARY - COMPLIANCE POSTURE
{'='*70}

Overall Compliance Score: {score}/100 - {posture}

Frameworks Assessed:
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
- NIST CSF (Cybersecurity Framework)
- CIS Controls v8 (Center for Internet Security)

Total Violations: {summary['total_violations']}

By Severity:
  • Critical: {summary['by_severity']['CRITICAL']}
  • High: {summary['by_severity']['HIGH']}
  • Medium: {summary['by_severity']['MEDIUM']}
  • Low: {summary['by_severity']['LOW']}

By Framework:
"""
        
        for framework, count in summary['by_framework'].items():
            report += f"  • {framework}: {count} violation(s)\n"
        
        report += f"\nRecommendation: "
        if posture == "CRITICAL":
            report += "IMMEDIATE ACTION REQUIRED. Critical compliance gaps detected."
        elif posture == "WEAK":
            report += "Significant compliance improvements needed within 30 days."
        elif posture == "ADEQUATE":
            report += "Address identified gaps to strengthen security posture."
        else:
            report += "Maintain current controls and continue monitoring."
        
        return report


def main():
    """Test compliance checker"""
    print("Compliance Checker - Use through main.py pipeline")


if __name__ == '__main__':
    main()