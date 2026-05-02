"""
Configuration Auditor Module
Detects security misconfigurations, weak credentials, and insecure settings.
"""

import socket
import ssl
import re
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Tuple
import base64


@dataclass
class ConfigIssue:
    """Represents a configuration security issue"""
    ip: str
    port: int
    service: str
    issue_type: str  # 'default_creds', 'weak_ssl', 'insecure_protocol', 'anonymous_access'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    title: str
    description: str
    remediation: str
    
    def to_dict(self):
        return asdict(self)


class ConfigAuditor:
    """
    Audits service configurations for security weaknesses.
    
    Checks:
    - Default credentials on common services
    - SSL/TLS version and cipher strength
    - Insecure protocols (cleartext authentication)
    - Anonymous access permissions
    - Common misconfigurations
    """
    
    # Common default credentials (service: [(username, password)])
    DEFAULT_CREDENTIALS = {
        'ssh': [
            ('root', 'root'), ('admin', 'admin'), ('root', 'toor'),
            ('admin', 'password'), ('root', ''), ('pi', 'raspberry')
        ],
        'ftp': [
            ('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin'),
            ('root', 'root'), ('user', 'user')
        ],
        'telnet': [
            ('admin', 'admin'), ('root', 'root'), ('admin', 'password'),
            ('admin', '1234'), ('admin', '')
        ],
        'mysql': [
            ('root', ''), ('root', 'root'), ('admin', 'admin'),
            ('root', 'password'), ('mysql', 'mysql')
        ],
        'postgresql': [
            ('postgres', 'postgres'), ('postgres', ''), ('admin', 'admin')
        ],
        'mongodb': [
            ('admin', 'admin'), ('root', 'root')
        ],
        'redis': [
            ('', '')  # No auth by default
        ],
        'vnc': [
            ('', 'password'), ('', '12345678'), ('', 'vnc123')
        ]
    }
    
    # Insecure protocols that transmit credentials in cleartext
    INSECURE_PROTOCOLS = {
        'ftp': {
            'title': 'FTP - Cleartext Protocol',
            'description': 'FTP transmits credentials and data in cleartext',
            'remediation': 'Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS (FTP Secure)'
        },
        'telnet': {
            'title': 'Telnet - Cleartext Protocol',
            'description': 'Telnet transmits all data including passwords in cleartext',
            'remediation': 'Replace Telnet with SSH for secure remote access'
        },
        'http': {
            'title': 'HTTP - Unencrypted Web Traffic',
            'description': 'HTTP transmits data without encryption, vulnerable to eavesdropping',
            'remediation': 'Enable HTTPS with valid TLS certificate'
        },
        'smtp': {
            'title': 'SMTP - Potential Cleartext Authentication',
            'description': 'SMTP may allow cleartext authentication if not properly configured',
            'remediation': 'Enforce TLS/SSL for SMTP connections (STARTTLS or SMTPS)'
        }
    }
    
    def __init__(self, timeout: float = 3.0):
        """Initialize configuration auditor"""
        self.timeout = timeout
        self.issues: List[ConfigIssue] = []
    
    def audit_service(self, ip: str, port: int, service: str, 
                     banner: Optional[str] = None) -> List[ConfigIssue]:
        """
        Audit a single service for configuration issues.
        
        Args:
            ip: Target IP
            port: Service port
            service: Service name
            banner: Service banner (optional)
        
        Returns:
            List of ConfigIssue objects
        """
        issues = []
        service_lower = service.lower()
        
        # Check for insecure protocols
        for proto in self.INSECURE_PROTOCOLS:
            if proto in service_lower:
                issue_info = self.INSECURE_PROTOCOLS[proto]
                issues.append(ConfigIssue(
                    ip=ip,
                    port=port,
                    service=service,
                    issue_type='insecure_protocol',
                    severity='HIGH',
                    title=issue_info['title'],
                    description=issue_info['description'],
                    remediation=issue_info['remediation']
                ))
        
        # Check SSL/TLS if HTTPS/SSL service
        if port in [443, 8443] or 'https' in service_lower or 'ssl' in service_lower:
            ssl_issues = self._check_ssl_tls(ip, port)
            issues.extend(ssl_issues)
        
        # Check for default credentials (ethical note: we test connection, not actual login)
        if service_lower in self.DEFAULT_CREDENTIALS:
            cred_issue = self._check_default_creds_risk(ip, port, service_lower)
            if cred_issue:
                issues.append(cred_issue)
        
        # Check for anonymous access
        if 'ftp' in service_lower:
            anon_issue = self._check_anonymous_ftp(ip, port)
            if anon_issue:
                issues.append(anon_issue)
        
        # Banner-based checks
        if banner:
            banner_issues = self._check_banner_disclosures(ip, port, service, banner)
            issues.extend(banner_issues)
        
        return issues
    
    def _check_ssl_tls(self, ip: str, port: int) -> List[ConfigIssue]:
        """Check SSL/TLS configuration for weaknesses"""
        issues = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to connect
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    # Get SSL/TLS version
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check for outdated protocols
                    if protocol_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        issues.append(ConfigIssue(
                            ip=ip,
                            port=port,
                            service='HTTPS/SSL',
                            issue_type='weak_ssl',
                            severity='HIGH',
                            title=f'Weak TLS Protocol: {protocol_version}',
                            description=f'Server supports outdated {protocol_version} protocol with known vulnerabilities',
                            remediation='Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1. Use TLSv1.2 or TLSv1.3 only'
                        ))
                    
                    # Check for weak ciphers
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']):
                            issues.append(ConfigIssue(
                                ip=ip,
                                port=port,
                                service='HTTPS/SSL',
                                issue_type='weak_ssl',
                                severity='HIGH',
                                title=f'Weak Cipher Suite: {cipher_name}',
                                description='Server supports weak cryptographic cipher',
                                remediation='Disable weak ciphers. Use strong ciphers like AES-GCM'
                            ))
        
        except ssl.SSLError as e:
            # SSL errors might indicate configuration issues
            if 'CERTIFICATE' in str(e).upper():
                issues.append(ConfigIssue(
                    ip=ip,
                    port=port,
                    service='HTTPS/SSL',
                    issue_type='weak_ssl',
                    severity='MEDIUM',
                    title='SSL Certificate Issue',
                    description=f'SSL certificate validation failed: {str(e)[:100]}',
                    remediation='Install valid SSL certificate from trusted CA'
                ))
        except Exception:
            pass  # Connection failed, skip SSL check
        
        return issues
    
    def _check_default_creds_risk(self, ip: str, port: int, service: str) -> Optional[ConfigIssue]:
        """
        Flag services that commonly have default credentials.
        
        Note: We DON'T actually test credentials (ethical boundary).
        We just warn that the service type is often misconfigured.
        """
        
        cred_count = len(self.DEFAULT_CREDENTIALS.get(service, []))
        
        return ConfigIssue(
            ip=ip,
            port=port,
            service=service.upper(),
            issue_type='default_creds',
            severity='CRITICAL',
            title=f'{service.upper()} - Default Credentials Risk',
            description=f'{service.upper()} service detected. This service type commonly ships with default credentials that are rarely changed. {cred_count} common default credential combinations exist for this service.',
            remediation=f'Ensure default credentials are changed. Use strong, unique passwords. Consider implementing key-based authentication for SSH or certificate-based auth where applicable.'
        )
    
    def _check_anonymous_ftp(self, ip: str, port: int) -> Optional[ConfigIssue]:
        """Check if FTP allows anonymous login"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Read banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for positive response (code 331 = username OK, need password)
            if '331' in response or '230' in response:
                sock.close()
                return ConfigIssue(
                    ip=ip,
                    port=port,
                    service='FTP',
                    issue_type='anonymous_access',
                    severity='HIGH',
                    title='FTP Anonymous Access Enabled',
                    description='FTP server accepts anonymous login attempts',
                    remediation='Disable anonymous FTP access unless explicitly required. Implement proper authentication'
                )
            
            sock.close()
        
        except Exception:
            pass  # Connection failed or doesn't support anonymous
        
        return None
    
    def _check_banner_disclosures(self, ip: str, port: int, service: str, 
                                  banner: str) -> List[ConfigIssue]:
        """Check banner for version disclosure and other info leaks"""
        issues = []
        
        # Check for detailed version information
        # Regex to find version numbers (e.g., "Apache/2.4.41", "OpenSSH_7.4")
        version_patterns = [
            r'[\w\-]+[/\_][\d\.]+',  # Software/1.2.3 or Software_1.2.3
            r'[\w\-]+\s+[\d\.]+',     # Software 1.2.3
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, banner):
                issues.append(ConfigIssue(
                    ip=ip,
                    port=port,
                    service=service,
                    issue_type='info_disclosure',
                    severity='LOW',
                    title='Service Version Disclosure',
                    description=f'Service banner reveals detailed version information: {banner[:100]}',
                    remediation='Configure service to hide version information in banners to reduce information leakage'
                ))
                break  # Only report once per service
        
        # Check for development/debug indicators
        debug_keywords = ['debug', 'test', 'dev', 'staging', 'development']
        banner_lower = banner.lower()
        
        for keyword in debug_keywords:
            if keyword in banner_lower:
                issues.append(ConfigIssue(
                    ip=ip,
                    port=port,
                    service=service,
                    issue_type='info_disclosure',
                    severity='MEDIUM',
                    title='Development/Debug Service Detected',
                    description=f'Service banner contains "{keyword}", suggesting non-production configuration',
                    remediation='Remove development services from production environments'
                ))
                break
        
        return issues
    
    def audit_multiple(self, services: List[Tuple[str, int, str, Optional[str]]]) -> List[ConfigIssue]:
        """
        Audit multiple services.
        
        Args:
            services: List of (ip, port, service, banner) tuples
        
        Returns:
            List of all ConfigIssue objects found
        """
        print(f"\n[*] Running configuration audit on {len(services)} service(s)...")
        
        self.issues = []
        
        for ip, port, service, banner in services:
            service_issues = self.audit_service(ip, port, service, banner)
            self.issues.extend(service_issues)
            
            if service_issues:
                print(f"[!] {ip}:{port} ({service}) - Found {len(service_issues)} issue(s)")
                for issue in service_issues:
                    print(f"    • [{issue.severity}] {issue.title}")
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        self.issues.sort(key=lambda x: severity_order.get(x.severity, 4))
        
        print(f"\n[*] Configuration audit complete. Found {len(self.issues)} issue(s)")
        
        return self.issues
    
    def get_summary(self) -> Dict:
        """Get summary statistics of configuration issues"""
        critical = len([i for i in self.issues if i.severity == 'CRITICAL'])
        high = len([i for i in self.issues if i.severity == 'HIGH'])
        medium = len([i for i in self.issues if i.severity == 'MEDIUM'])
        low = len([i for i in self.issues if i.severity == 'LOW'])
        
        return {
            'total_issues': len(self.issues),
            'by_severity': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low
            },
            'by_type': {
                'insecure_protocol': len([i for i in self.issues if i.issue_type == 'insecure_protocol']),
                'default_creds': len([i for i in self.issues if i.issue_type == 'default_creds']),
                'weak_ssl': len([i for i in self.issues if i.issue_type == 'weak_ssl']),
                'anonymous_access': len([i for i in self.issues if i.issue_type == 'anonymous_access']),
                'info_disclosure': len([i for i in self.issues if i.issue_type == 'info_disclosure'])
            }
        }


def main():
    """CLI for standalone testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Configuration Auditor')
    parser.add_argument('--test', action='store_true', help='Run test audit')
    
    args = parser.parse_args()
    
    if args.test:
        # Test with sample services
        auditor = ConfigAuditor()
        
        test_services = [
            ('192.168.1.100', 21, 'FTP', 'ProFTPD 1.3.5 Server'),
            ('192.168.1.100', 23, 'Telnet', 'Ubuntu 20.04 LTS'),
            ('192.168.1.100', 22, 'SSH', 'OpenSSH_7.4'),
            ('192.168.1.100', 80, 'HTTP', 'Apache/2.4.41 (Ubuntu)')
        ]
        
        auditor.audit_multiple(test_services)
        
        summary = auditor.get_summary()
        print(f"\n[SUMMARY]")
        print(f"Total issues: {summary['total_issues']}")
        print(f"  Critical: {summary['by_severity']['critical']}")
        print(f"  High: {summary['by_severity']['high']}")


if __name__ == '__main__':
    main()