import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Optional
import argparse
import json


@dataclass
class ScanResult:
    ip: str
    port: int
    state: str
    service: Optional[str] = None
    banner: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)


class NetworkScanner:

    
    # Common ports for initial reconnaissance
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
        993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443
    ]
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):

        self.timeout = timeout
        self.max_workers = max_workers
        self.results: List[ScanResult] = []
    
    def parse_targets(self, target: str) -> List[str]:

        try:
            # Try parsing as CIDR network
            network = ipaddress.ip_network(target, strict=False)
            # For /24 networks, this could be 254 hosts
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Single IP address
            return [target]
    
    def scan_port(self, ip: str, port: int) -> Optional[ScanResult]:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port is open - try to identify service
                banner = self._grab_banner(sock, port)
                service = self._guess_service(port, banner)
                
                sock.close()
                return ScanResult(
                    ip=ip,
                    port=port,
                    state='open',
                    service=service,
                    banner=banner
                )
            
            sock.close()
            return None
            
        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            return None
    
    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:

        try:
            sock.settimeout(0.5)
            
            # Some services send banner immediately
            banner = sock.recv(1024)
            
            # HTTP servers need a request
            if len(banner) == 0 and port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                banner = sock.recv(1024)
            
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()[:200]
            
        except Exception:
            pass
        
        return None
    
    def _guess_service(self, port: int, banner: Optional[str] = None) -> str:

        # Try banner-based identification first
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                return 'SSH'
            if 'http' in banner_lower or 'html' in banner_lower:
                return 'HTTP'
            if 'ftp' in banner_lower:
                return 'FTP'
            if 'smtp' in banner_lower:
                return 'SMTP'
        
        # Fall back to port-based identification
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        
        return service_map.get(port, 'Unknown')
    
    def scan(self, targets: str, ports: List[int] = None) -> List[ScanResult]:

        if ports is None:
            ports = self.COMMON_PORTS
        
        ip_list = self.parse_targets(targets)
        self.results = []
        
        total_checks = len(ip_list) * len(ports)
        print(f"[*] Scanning {len(ip_list)} host(s) across {len(ports)} port(s)")
        print(f"[*] Total checks: {total_checks}")
        
        # Create all scan tasks
        tasks = [(ip, port) for ip in ip_list for port in ports]
        
        # Execute scans concurrently
        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {
                executor.submit(self.scan_port, ip, port): (ip, port)
                for ip, port in tasks
            }
            
            for future in as_completed(future_to_task):
                completed += 1
                if completed % 100 == 0:
                    print(f"[*] Progress: {completed}/{total_checks}")
                
                result = future.result()
                if result:
                    self.results.append(result)
                    print(f"[+] {result.ip}:{result.port} ({result.service}) - OPEN")
                    if result.banner:
                        print(f"    Banner: {result.banner[:80]}")
        
        print(f"\n[*] Scan complete. Found {len(self.results)} open port(s)")
        return self.results
    
    def export_json(self, filename: str):
        """Export results to JSON file"""
        data = {
            'scan_summary': {
                'total_hosts_scanned': len(set(r.ip for r in self.results)),
                'total_open_ports': len(self.results),
            },
            'findings': [r.to_dict() for r in self.results]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[*] Results exported to {filename}")


def main():
    """CLI interface for standalone usage"""
    parser = argparse.ArgumentParser(
        description='Network Scanner - Discover open ports and services'
    )
    parser.add_argument('target', help='Target IP or CIDR range (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Comma-separated ports (default: common ports)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    
    args = parser.parse_args()
    
    # Parse ports if provided
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        ports = None
    
    # Run scan
    scanner = NetworkScanner(timeout=args.timeout)
    results = scanner.scan(args.target, ports)
    
    # Export if requested
    if args.output:
        scanner.export_json(args.output)


if __name__ == '__main__':
    main()