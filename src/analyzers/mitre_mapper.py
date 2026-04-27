"""
MITRE ATT&CK Mapper
Maps discovered services and vulnerabilities to MITRE ATT&CK techniques.
"""

import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from pathlib import Path


@dataclass
class AttackTechnique:
    """Represents a MITRE ATT&CK technique"""
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    detection: Optional[str] = None
    url: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)


@dataclass
class MappedFinding:
    """A service finding mapped to MITRE techniques"""
    ip: str
    port: int
    service: str
    version: Optional[str]
    techniques: List[AttackTechnique]
    risk_score: float
    rationale: str
    
    def to_dict(self):
        return {
            'ip': self.ip,
            'port': self.port,
            'service': self.service,
            'version': self.version,
            'techniques': [t.to_dict() for t in self.techniques],
            'risk_score': self.risk_score,
            'rationale': self.rationale
        }


class MITREMapper:
    """
    Maps network findings to MITRE ATT&CK framework.
    
    Architecture:
    - Loads MITRE Enterprise ATT&CK data
    - Maintains service-to-technique mappings
    - Calculates risk scores based on multiple factors
    - Returns enriched findings for reporting
    """
    
    MITRE_DATA_PATH = "data/mitre_enterprise.json"
    
    # Service-to-Technique mapping (curated based on real attack patterns)
    SERVICE_MAPPINGS = {
        'ssh': {
            'techniques': ['T1021.004'],  # Remote Services: SSH
            'rationale': 'SSH exposed allows remote access if credentials compromised'
        },
        'rdp': {
            'techniques': ['T1021.001'],  # Remote Services: RDP
            'rationale': 'RDP is a common target for credential attacks and exploitation'
        },
        'smb': {
            'techniques': ['T1021.002', 'T1570'],  # SMB/Windows Admin Shares, Lateral Tool Transfer
            'rationale': 'SMB can be used for lateral movement and file transfer'
        },
        'http': {
            'techniques': ['T1190', 'T1583.006'],  # Exploit Public-Facing Application, Web Services
            'rationale': 'Web servers are prime targets for exploitation and reconnaissance'
        },
        'https': {
            'techniques': ['T1190', 'T1583.006'],
            'rationale': 'HTTPS services may have vulnerabilities in web applications or SSL/TLS'
        },
        'ftp': {
            'techniques': ['T1021.002', 'T1048.003'],  # FTP, Exfiltration Over Alternative Protocol
            'rationale': 'FTP can be used for data exfiltration and often has weak authentication'
        },
        'telnet': {
            'techniques': ['T1021.004', 'T1040'],  # Remote Services, Network Sniffing
            'rationale': 'Telnet transmits credentials in cleartext and provides remote access'
        },
        'smtp': {
            'techniques': ['T1566.001', 'T1114'],  # Phishing: Spearphishing Attachment, Email Collection
            'rationale': 'SMTP servers can be used for phishing and email reconnaissance'
        },
        'mysql': {
            'techniques': ['T1078', 'T1213'],  # Valid Accounts, Data from Information Repositories
            'rationale': 'Database access can lead to credential theft and data exfiltration'
        },
        'postgresql': {
            'techniques': ['T1078', 'T1213'],
            'rationale': 'PostgreSQL access enables data theft and potential privilege escalation'
        },
        'mssql': {
            'techniques': ['T1078', 'T1213', 'T1059.001'],  # Valid Accounts, Data Repos, PowerShell
            'rationale': 'MSSQL can execute commands via xp_cmdshell and access sensitive data'
        },
        'vnc': {
            'techniques': ['T1021.005'],  # Remote Services: VNC
            'rationale': 'VNC provides graphical remote access, often with weak authentication'
        },
        'dns': {
            'techniques': ['T1071.004', 'T1583.002'],  # Application Layer Protocol: DNS, Domain
            'rationale': 'DNS can be used for C2 communication and data exfiltration'
        }
    }
    
    def __init__(self):
        """Initialize MITRE mapper and load framework data"""
        self.techniques_db: Dict[str, AttackTechnique] = {}
        self.tactics_db: Dict[str, str] = {}
        self._load_mitre_data()
        self.mapped_findings: List[MappedFinding] = []
    
    def _load_mitre_data(self):
        """Load and parse MITRE ATT&CK Enterprise data"""
        print("[*] Loading MITRE ATT&CK framework data...")
        
        if not Path(self.MITRE_DATA_PATH).exists():
            raise FileNotFoundError(
                f"MITRE data not found at {self.MITRE_DATA_PATH}. "
                f"Run scripts/download_mitre_data.py first."
            )
        
        with open(self.MITRE_DATA_PATH, 'r') as f:
            data = json.load(f)
        
        # Parse techniques
        for obj in data['objects']:
            if obj['type'] == 'attack-pattern' and not obj.get('revoked', False):
                # Extract technique ID
                external_refs = obj.get('external_references', [])
                technique_id = None
                url = None
                
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        url = ref.get('url')
                        break
                
                if not technique_id:
                    continue
                
                # Extract tactics (kill chain phases)
                tactics = []
                kill_chain = obj.get('kill_chain_phases', [])
                for phase in kill_chain:
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.append(phase.get('phase_name'))
                
                technique = AttackTechnique(
                    technique_id=technique_id,
                    name=obj.get('name', 'Unknown'),
                    description=obj.get('description', '')[:300],  # Truncate
                    tactics=tactics,
                    detection=obj.get('x_mitre_detection', None),
                    url=url
                )
                
                self.techniques_db[technique_id] = technique
        
        print(f"[+] Loaded {len(self.techniques_db)} MITRE ATT&CK techniques")
    
    def map_service(self, ip: str, port: int, service: str, version: str = None,
                    vulnerabilities: List = None) -> Optional[MappedFinding]:
        """
        Map a discovered service to MITRE ATT&CK techniques.
        
        Args:
            ip: Target IP
            port: Service port
            service: Service name (e.g., 'ssh', 'http')
            version: Service version (optional)
            vulnerabilities: List of CVEs (optional)
        
        Returns:
            MappedFinding with techniques and risk score
        """
        service_lower = service.lower()
        
        # Check if we have a mapping for this service
        mapping = None
        for key in self.SERVICE_MAPPINGS:
            if key in service_lower:
                mapping = self.SERVICE_MAPPINGS[key]
                break
        
        if not mapping:
            # No specific mapping, but we can still map generic exposed services
            mapping = {
                'techniques': ['T1046'],  # Network Service Discovery
                'rationale': f'Exposed {service} service increases attack surface'
            }
        
        # Get full technique details
        techniques = []
        for tech_id in mapping['techniques']:
            if tech_id in self.techniques_db:
                techniques.append(self.techniques_db[tech_id])
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            service=service_lower,
            port=port,
            version=version,
            vulnerabilities=vulnerabilities,
            techniques=techniques
        )
        
        mapped_finding = MappedFinding(
            ip=ip,
            port=port,
            service=service,
            version=version,
            techniques=techniques,
            risk_score=risk_score,
            rationale=mapping['rationale']
        )
        
        return mapped_finding
    
    def _calculate_risk_score(self, service: str, port: int, version: str,
                             vulnerabilities: List, techniques: List[AttackTechnique]) -> float:
        """
        Calculate risk score (0-10) based on multiple factors.
        
        Factors:
        - Service type (some are riskier than others)
        - Number of associated attack techniques
        - Presence of known vulnerabilities
        - Port exposure (well-known vs non-standard)
        """
        score = 0.0
        
        # Base score by service risk
        high_risk_services = ['telnet', 'ftp', 'vnc', 'rdp', 'smb']
        medium_risk_services = ['ssh', 'mysql', 'postgresql', 'mssql']
        
        if any(risky in service for risky in high_risk_services):
            score += 4.0
        elif any(risky in service for risky in medium_risk_services):
            score += 2.5
        else:
            score += 1.5
        
        # Add points for number of techniques
        score += min(len(techniques) * 0.5, 2.0)
        
        # Major points for known vulnerabilities
        if vulnerabilities:
            vuln_count = len(vulnerabilities)
            score += min(vuln_count * 0.8, 3.0)
            
            # Extra points for high-severity CVEs
            high_severity = sum(1 for v in vulnerabilities 
                              if hasattr(v, 'severity') and v.severity in ['HIGH', 'CRITICAL'])
            score += min(high_severity * 0.5, 1.5)
        
        # Cap at 10.0
        return min(round(score, 1), 10.0)
    
    def map_findings(self, service_findings: List) -> List[MappedFinding]:
        """
        Map multiple service findings to MITRE techniques.
        
        Args:
            service_findings: List of ServiceInfo objects from service_enumerator
        
        Returns:
            List of MappedFinding objects
        """
        print(f"\n[*] Mapping {len(service_findings)} findings to MITRE ATT&CK...")
        
        self.mapped_findings = []
        
        for finding in service_findings:
            mapped = self.map_service(
                ip=finding.ip,
                port=finding.port,
                service=finding.service,
                version=finding.version,
                vulnerabilities=finding.vulnerabilities if hasattr(finding, 'vulnerabilities') else None
            )
            
            if mapped:
                self.mapped_findings.append(mapped)
                print(f"[+] {finding.ip}:{finding.port} ({finding.service}) → "
                      f"{len(mapped.techniques)} technique(s), Risk: {mapped.risk_score}/10")
        
        # Sort by risk score (highest first)
        self.mapped_findings.sort(key=lambda x: x.risk_score, reverse=True)
        
        return self.mapped_findings
    
    def get_attack_summary(self) -> Dict:
        """Generate attack surface summary"""
        if not self.mapped_findings:
            return {}
        
        # Collect all unique techniques
        all_techniques: Set[str] = set()
        all_tactics: Set[str] = set()
        
        for finding in self.mapped_findings:
            for tech in finding.techniques:
                all_techniques.add(tech.technique_id)
                all_tactics.update(tech.tactics)
        
        # Risk distribution
        critical = len([f for f in self.mapped_findings if f.risk_score >= 7.0])
        high = len([f for f in self.mapped_findings if 5.0 <= f.risk_score < 7.0])
        medium = len([f for f in self.mapped_findings if 3.0 <= f.risk_score < 5.0])
        low = len([f for f in self.mapped_findings if f.risk_score < 3.0])
        
        return {
            'total_findings': len(self.mapped_findings),
            'unique_techniques': len(all_techniques),
            'tactics_covered': list(all_tactics),
            'risk_distribution': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low
            },
            'top_risks': [f.to_dict() for f in self.mapped_findings[:5]]
        }
    
    def export_json(self, filename: str):
        """Export mapped findings to JSON"""
        data = {
            'mitre_mapping_summary': self.get_attack_summary(),
            'mapped_findings': [f.to_dict() for f in self.mapped_findings]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[*] MITRE mappings exported to {filename}")


def main():
    """CLI for standalone testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MITRE ATT&CK Mapper')
    parser.add_argument('--test', action='store_true', help='Run test mapping')
    
    args = parser.parse_args()
    
    if args.test:
        # Test with sample data
        from dataclasses import dataclass
        
        @dataclass
        class TestService:
            ip: str
            port: int
            service: str
            version: str
            vulnerabilities: list
        
        mapper = MITREMapper()
        
        test_services = [
            TestService('192.168.1.100', 22, 'SSH', '7.4', []),
            TestService('192.168.1.100', 80, 'HTTP', 'Apache 2.4', []),
            TestService('192.168.1.100', 3389, 'RDP', 'Windows', [])
        ]
        
        mapper.map_findings(test_services)
        mapper.export_json('reports/mitre_test.json')
        
        print("\n[SUMMARY]")
        summary = mapper.get_attack_summary()
        print(f"Total techniques identified: {summary['unique_techniques']}")
        print(f"Tactics covered: {', '.join(summary['tactics_covered'])}")


if __name__ == '__main__':
    main()