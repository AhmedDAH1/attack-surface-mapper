import nmap
import requests
import json
import time
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from datetime import datetime, timedelta


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    
    def to_dict(self):
        return asdict(self)


@dataclass
class ServiceInfo:
    ip: str
    port: int
    service: str
    version: Optional[str] = None
    product: Optional[str] = None
    cpe: Optional[str] = None  # Common Platform Enumeration
    vulnerabilities: List[Vulnerability] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
    
    def to_dict(self):
        return {
            'ip': self.ip,
            'port': self.port,
            'service': self.service,
            'version': self.version,
            'product': self.product,
            'cpe': self.cpe,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }


class ServiceEnumerator:
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_FILE = "data/cve_cache.json"
    RATE_LIMIT_DELAY = 6  # NVD allows 5 requests per 30 seconds without API key
    
    def __init__(self, use_cve_lookup: bool = True):
        """
        Initialize service enumerator.
        
        Args:
            use_cve_lookup: Whether to query NVD for CVEs (slower but more thorough)
        """
        self.nm = nmap.PortScanner()
        self.use_cve_lookup = use_cve_lookup
        self.cve_cache = self._load_cache()
        self.results: List[ServiceInfo] = []
    
    def _load_cache(self) -> Dict:
        """Load CVE cache from disk"""
        try:
            with open(self.CACHE_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def _save_cache(self):
        """Save CVE cache to disk"""
        import os
        os.makedirs('data', exist_ok=True)
        with open(self.CACHE_FILE, 'w') as f:
            json.dump(self.cve_cache, f, indent=2)
    
    def enumerate_service(self, ip: str, port: int) -> Optional[ServiceInfo]:
        print(f"[*] Enumerating {ip}:{port}...")
        
        try:
            # Use nmap for version detection
            # -sV: Version detection
            # -Pn: Skip ping (assume host is up)
            self.nm.scan(ip, str(port), arguments='-sV -Pn')
            
            if ip not in self.nm.all_hosts():
                return None
            
            if 'tcp' not in self.nm[ip]:
                return None
            
            if port not in self.nm[ip]['tcp']:
                return None
            
            port_info = self.nm[ip]['tcp'][port]
            
            # Extract service information
            service_name = port_info.get('name', 'unknown')
            product = port_info.get('product', '')
            version = port_info.get('version', '')
            cpe = port_info.get('cpe', '')
            
            # Create service info object
            service_info = ServiceInfo(
                ip=ip,
                port=port,
                service=service_name,
                version=version if version else None,
                product=product if product else None,
                cpe=cpe if cpe else None
            )
            
            # Look up CVEs if enabled and we have version info
            if self.use_cve_lookup and (product or cpe):
                vulnerabilities = self._lookup_cves(product, version, cpe)
                service_info.vulnerabilities = vulnerabilities
            
            print(f"[+] {ip}:{port} - {product} {version}")
            if service_info.vulnerabilities:
                print(f"    Found {len(service_info.vulnerabilities)} CVE(s)")
            
            return service_info
            
        except Exception as e:
            print(f"[!] Error enumerating {ip}:{port}: {e}")
            return None
    
    def _lookup_cves(self, product: str, version: str, cpe: str) -> List[Vulnerability]:
        """
        Query NVD for known CVEs affecting this service.
        
        Args:
            product: Product name (e.g., "OpenSSH")
            version: Version string (e.g., "7.4")
            cpe: Common Platform Enumeration string
            
        Returns:
            List of Vulnerability objects
        """
        # Create cache key
        cache_key = f"{product}:{version}" if product else cpe
        
        # Check cache first
        if cache_key in self.cve_cache:
            cached = self.cve_cache[cache_key]
            # Cache valid for 7 days
            cache_date = datetime.fromisoformat(cached['timestamp'])
            if datetime.now() - cache_date < timedelta(days=7):
                print(f"    [Cache hit] {cache_key}")
                return [Vulnerability(**v) for v in cached['vulns']]
        
        # Not in cache or expired - query NVD
        print(f"    [Querying NVD] {cache_key}")
        vulnerabilities = []
        
        try:
            # Respect rate limits
            time.sleep(self.RATE_LIMIT_DELAY)
            
            # Build query - search by keyword (product + version)
            search_term = f"{product} {version}".strip() if product else cpe
            
            params = {
                'keywordSearch': search_term,
                'resultsPerPage': 10  # Limit to top 10 most relevant
            }
            
            response = requests.get(self.NVD_API_BASE, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if 'vulnerabilities' in data:
                for item in data['vulnerabilities']:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    
                    # Extract description
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                    
                    # Extract CVSS score
                    metrics = cve.get('metrics', {})
                    cvss_score = 0.0
                    severity = 'UNKNOWN'
                    
                    # Try CVSS v3 first, fall back to v2
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = self._cvss_v2_to_severity(cvss_score)
                    
                    published = cve.get('published', 'Unknown')
                    
                    vuln = Vulnerability(
                        cve_id=cve_id,
                        description=description[:200],  # Truncate long descriptions
                        severity=severity,
                        cvss_score=cvss_score,
                        published_date=published
                    )
                    
                    vulnerabilities.append(vuln)
            
            # Cache the results
            self.cve_cache[cache_key] = {
                'timestamp': datetime.now().isoformat(),
                'vulns': [v.to_dict() for v in vulnerabilities]
            }
            self._save_cache()
            
        except requests.exceptions.RequestException as e:
            print(f"    [!] NVD API error: {e}")
        except Exception as e:
            print(f"    [!] CVE lookup error: {e}")
        
        return vulnerabilities
    
    def _cvss_v2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity rating"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def enumerate_multiple(self, targets: List[tuple]) -> List[ServiceInfo]:
        """
        Enumerate multiple targets.
        
        Args:
            targets: List of (ip, port) tuples
            
        Returns:
            List of ServiceInfo objects
        """
        self.results = []
        
        print(f"[*] Starting service enumeration on {len(targets)} target(s)")
        
        for ip, port in targets:
            service_info = self.enumerate_service(ip, port)
            if service_info:
                self.results.append(service_info)
        
        print(f"\n[*] Enumeration complete. Analyzed {len(self.results)} service(s)")
        return self.results
    
    def export_json(self, filename: str):
        """Export enriched results to JSON"""
        data = {
            'enumeration_summary': {
                'total_services': len(self.results),
                'services_with_vulns': len([s for s in self.results if s.vulnerabilities]),
                'total_cves': sum(len(s.vulnerabilities) for s in self.results)
            },
            'services': [s.to_dict() for s in self.results]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[*] Results exported to {filename}")


def main():
    """CLI for standalone testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Service Enumerator - Deep service analysis')
    parser.add_argument('ip', help='Target IP address')
    parser.add_argument('port', type=int, help='Target port')
    parser.add_argument('--no-cve', action='store_true', help='Skip CVE lookup')
    parser.add_argument('-o', '--output', help='Export to JSON file')
    
    args = parser.parse_args()
    
    enumerator = ServiceEnumerator(use_cve_lookup=not args.no_cve)
    result = enumerator.enumerate_service(args.ip, args.port)
    
    if result and args.output:
        enumerator.results = [result]
        enumerator.export_json(args.output)


if __name__ == '__main__':
    main()