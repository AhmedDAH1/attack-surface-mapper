"""
Test Fixtures and Sample Data
Provides mock data for testing.
"""

# Sample scan results
SAMPLE_SCAN_RESULTS = [
    {
        'ip': '192.168.1.100',
        'port': 22,
        'service': 'ssh',
        'banner': 'SSH-2.0-OpenSSH_7.4',
        'state': 'open'
    },
    {
        'ip': '192.168.1.100',
        'port': 80,
        'service': 'http',
        'banner': 'Apache/2.4.41',
        'state': 'open'
    },
    {
        'ip': '192.168.1.100',
        'port': 443,
        'service': 'https',
        'banner': None,
        'state': 'open'
    }
]

# Sample service enumeration results
SAMPLE_SERVICES = [
    {
        'ip': '192.168.1.100',
        'port': 22,
        'service': 'ssh',
        'product': 'OpenSSH',
        'version': '7.4',
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2018-15473',
                'description': 'Username enumeration vulnerability',
                'cvss_score': 5.3,
                'severity': 'MEDIUM'
            }
        ]
    },
    {
        'ip': '192.168.1.100',
        'port': 80,
        'service': 'http',
        'product': 'Apache',
        'version': '2.4.41',
        'vulnerabilities': []
    }
]

# Sample configuration issues
SAMPLE_CONFIG_ISSUES = [
    {
        'ip': '192.168.1.100',
        'port': 80,
        'severity': 'HIGH',
        'issue_type': 'insecure_protocol',
        'title': 'HTTP - Unencrypted Web Traffic',
        'description': 'Web server uses unencrypted HTTP protocol',
        'remediation': 'Enable HTTPS with TLS 1.2 or higher'
    },
    {
        'ip': '192.168.1.100',
        'port': 22,
        'severity': 'MEDIUM',
        'issue_type': 'info_disclosure',
        'title': 'SSH Version Disclosure',
        'description': 'SSH banner reveals version information',
        'remediation': 'Configure SSH to hide version in banner'
    }
]

# Sample MITRE ATT&CK mappings
SAMPLE_MITRE_MAPPINGS = [
    {
        'technique_id': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'service': 'http',
        'port': 80
    },
    {
        'technique_id': 'T1021.004',
        'technique_name': 'Remote Services: SSH',
        'tactic': 'Lateral Movement',
        'service': 'ssh',
        'port': 22
    }
]

# Sample compliance violations
SAMPLE_COMPLIANCE_VIOLATIONS = [
    {
        'framework': 'PCI-DSS v4.0',
        'control_id': 'PCI-DSS 4.1',
        'control_name': 'Use Strong Cryptography',
        'severity': 'HIGH',
        'description': 'Unencrypted HTTP traffic violates PCI-DSS 4.1'
    }
]

# Sample analytics data
SAMPLE_ANALYTICS_HISTORY = [
    {
        'scan_id': '20260101_120000',
        'timestamp': '2026-01-01T12:00:00',
        'target': '192.168.1.100',
        'metrics': {
            'ports_open': 3,
            'services_found': 3,
            'vulnerabilities': 1,
            'critical_issues': 0,
            'high_issues': 1,
            'compliance_score': 70
        }
    },
    {
        'scan_id': '20260102_120000',
        'timestamp': '2026-01-02T12:00:00',
        'target': '192.168.1.100',
        'metrics': {
            'ports_open': 3,
            'services_found': 3,
            'vulnerabilities': 2,
            'critical_issues': 1,
            'high_issues': 1,
            'compliance_score': 60
        }
    }
]
