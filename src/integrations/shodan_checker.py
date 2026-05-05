"""
Shodan Integration
Check if services are exposed on the public internet via Shodan.
"""

import shodan
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class ShodanExposure:
    """Represents Shodan exposure finding"""
    ip: str
    port: int
    service: str
    exposed_globally: bool
    shodan_data: Optional[Dict] = None
    hostnames: List[str] = None
    countries: List[str] = None
    organizations: List[str] = None
    last_update: Optional[str] = None
    
    def __post_init__(self):
        if self.hostnames is None:
            self.hostnames = []
        if self.countries is None:
            self.countries = []
        if self.organizations is None:
            self.organizations = []
    
    def to_dict(self):
        return asdict(self)


class ShodanChecker:
    """
    Check service exposure via Shodan.
    
    Features:
    - Check if IP is indexed in Shodan
    - Identify exposed services
    - Get geolocation and organization data
    - Detect open ports visible from internet
    """
    
    def __init__(self, api_key: str):
        """
        Initialize Shodan checker.
        
        Args:
            api_key: Shodan API key (get free at shodan.io)
        """
        self.api_key = api_key
        self.api = shodan.Shodan(api_key)
        self.results: List[ShodanExposure] = []
    
    def check_ip_exposure(self, ip: str, local_ports: List[int]) -> Optional[ShodanExposure]:
        """
        Check if IP and services are exposed via Shodan.
        
        Args:
            ip: IP address to check
            local_ports: Ports found locally
        
        Returns:
            ShodanExposure object
        """
        
        # Skip private IPs
        if self._is_private_ip(ip):
            print(f"[*] Skipping Shodan check for private IP: {ip}")
            return None
        
        try:
            print(f"[*] Checking Shodan for {ip}...")
            
            # Query Shodan
            host = self.api.host(ip)
            
            # Extract data
            exposed_ports = [item['port'] for item in host.get('data', [])]
            hostnames = host.get('hostnames', [])
            country = host.get('country_name', 'Unknown')
            org = host.get('org', 'Unknown')
            last_update = host.get('last_update', 'Unknown')
            
            # Check if any local ports are exposed
            exposed_locally = set(local_ports).intersection(set(exposed_ports))
            
            exposure = ShodanExposure(
                ip=ip,
                port=0,  # Multiple ports
                service='Multiple',
                exposed_globally=len(exposed_ports) > 0,
                shodan_data={
                    'total_exposed_ports': len(exposed_ports),
                    'exposed_ports': exposed_ports,
                    'locally_found_exposed': list(exposed_locally),
                    'vulns': host.get('vulns', []),
                    'tags': host.get('tags', [])
                },
                hostnames=hostnames,
                countries=[country],
                organizations=[org],
                last_update=last_update
            )
            
            if exposed_globally:
                print(f"[!] ALERT: {ip} is exposed on Shodan with {len(exposed_ports)} open port(s)")
                if exposed_locally:
                    print(f"    WARNING: {len(exposed_locally)} port(s) you found are visible globally: {list(exposed_locally)}")
            else:
                print(f"[✓] {ip} not found in Shodan (good - not globally exposed)")
            
            return exposure
        
        except shodan.APIError as e:
            if "No information available" in str(e):
                print(f"[✓] {ip} not found in Shodan (not exposed)")
                return ShodanExposure(
                    ip=ip, port=0, service='None', exposed_globally=False
                )
            else:
                print(f"[!] Shodan API error for {ip}: {e}")
                return None
        
        except Exception as e:
            print(f"[!] Error checking Shodan for {ip}: {e}")
            return None
    
    def check_multiple(self, targets: List[tuple]) -> List[ShodanExposure]:
        """
        Check multiple IPs via Shodan.
        
        Args:
            targets: List of (ip, ports) tuples
        
        Returns:
            List of ShodanExposure objects
        """
        print(f"\n[*] Checking {len(targets)} target(s) against Shodan...")
        
        self.results = []
        
        # Group ports by IP
        ip_ports = {}
        for ip, port in targets:
            if ip not in ip_ports:
                ip_ports[ip] = []
            ip_ports[ip].append(port)
        
        # Check each IP once
        for ip, ports in ip_ports.items():
            exposure = self.check_ip_exposure(ip, ports)
            if exposure:
                self.results.append(exposure)
        
        print(f"\n[*] Shodan check complete. Found {len([r for r in self.results if r.exposed_globally])} exposed IP(s)")
        
        return self.results
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    def get_summary(self) -> Dict:
        """Get Shodan check summary"""
        exposed = [r for r in self.results if r.exposed_globally]
        
        return {
            'total_ips_checked': len(self.results),
            'globally_exposed': len(exposed),
            'not_exposed': len(self.results) - len(exposed),
            'total_exposed_ports': sum(r.shodan_data.get('total_exposed_ports', 0) for r in exposed if r.shodan_data),
            'exposed_ips': [r.ip for r in exposed]
        }


def main():
    """Test Shodan checker"""
    print("Shodan Checker - Use through main.py with --shodan-key flag")
    print("\nGet a free API key at: https://account.shodan.io/register")
    print("Free tier: 100 query credits/month")


if __name__ == '__main__':
    main()