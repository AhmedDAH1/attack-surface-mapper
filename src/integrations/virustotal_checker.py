"""
VirusTotal Integration
Check IP/domain/URL reputation via VirusTotal.
"""

import vt
from typing import Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class VTReputation:
    """Represents VirusTotal reputation check"""
    target: str
    target_type: str  # 'ip', 'domain', 'url'
    malicious_score: int
    suspicious_score: int
    harmless_score: int
    total_vendors: int
    reputation: int  # Overall reputation score
    categories: Dict
    is_malicious: bool
    
    def to_dict(self):
        return asdict(self)


class VirusTotalChecker:
    """
    Check reputation via VirusTotal.
    
    Features:
    - IP reputation checking
    - Domain reputation
    - URL scanning
    - Malware detection scores
    """
    
    def __init__(self, api_key: str):
        """
        Initialize VirusTotal checker.
        
        Args:
            api_key: VirusTotal API key (free at virustotal.com)
        """
        self.api_key = api_key
        self.client = vt.Client(api_key)
        self.results = []
    
    def check_ip_reputation(self, ip: str) -> Optional[VTReputation]:
        """
        Check IP reputation.
        
        Args:
            ip: IP address
        
        Returns:
            VTReputation object
        """
        
        # Skip private IPs
        if self._is_private_ip(ip):
            print(f"[*] Skipping VirusTotal check for private IP: {ip}")
            return None
        
        try:
            print(f"[*] Checking VirusTotal reputation for {ip}...")
            
            ip_obj = self.client.get_object(f"/ip_addresses/{ip}")
            
            # Get analysis stats
            stats = ip_obj.last_analysis_stats
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            
            total = malicious + suspicious + harmless + undetected
            
            # Get categories
            categories = ip_obj.get('categories', {})
            
            # Overall reputation
            reputation = ip_obj.get('reputation', 0)
            
            is_malicious = malicious > 0 or suspicious > 2
            
            vt_rep = VTReputation(
                target=ip,
                target_type='ip',
                malicious_score=malicious,
                suspicious_score=suspicious,
                harmless_score=harmless,
                total_vendors=total,
                reputation=reputation,
                categories=categories,
                is_malicious=is_malicious
            )
            
            if is_malicious:
                print(f"[!] WARNING: {ip} flagged by {malicious} vendor(s) as malicious!")
            else:
                print(f"[✓] {ip} clean - No malicious flags")
            
            return vt_rep
        
        except vt.APIError as e:
            print(f"[!] VirusTotal API error for {ip}: {e}")
            return None
        
        except Exception as e:
            print(f"[!] Error checking VirusTotal for {ip}: {e}")
            return None
    
    def check_multiple_ips(self, ips: List[str]) -> List[VTReputation]:
        """Check multiple IPs"""
        print(f"\n[*] Checking {len(ips)} IP(s) against VirusTotal...")
        
        self.results = []
        unique_ips = list(set(ips))
        
        for ip in unique_ips:
            rep = self.check_ip_reputation(ip)
            if rep:
                self.results.append(rep)
        
        malicious_count = len([r for r in self.results if r.is_malicious])
        
        print(f"\n[*] VirusTotal check complete. {malicious_count} malicious IP(s) detected")
        
        return self.results
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    def get_summary(self) -> Dict:
        """Get summary"""
        malicious = [r for r in self.results if r.is_malicious]
        
        return {
            'total_checked': len(self.results),
            'malicious': len(malicious),
            'clean': len(self.results) - len(malicious),
            'malicious_ips': [r.target for r in malicious]
        }
    
    def close(self):
        """Close VirusTotal client"""
        self.client.close()


def main():
    """Test VirusTotal checker"""
    print("VirusTotal Checker - Use through main.py with --vt-key flag")
    print("\nGet a free API key at: https://www.virustotal.com/gui/join-us")
    print("Free tier: 500 requests/day, 4 requests/minute")


if __name__ == '__main__':
    main()