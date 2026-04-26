#!/usr/bin/env python3
"""
Attack Surface Mapper
Main entry point that orchestrates all scanning and analysis modules.
"""

import argparse
import sys
from src.scanners.network_scanner import NetworkScanner
from src.scanners.service_enumerator import ServiceEnumerator


def run_scan(target: str, ports: list = None, skip_enumeration: bool = False, 
             skip_cve: bool = False, output: str = None):
    """
    Run complete attack surface scan.
    
    Pipeline:
    1. Network Scanner - Discover open ports
    2. Service Enumerator - Identify versions and CVEs
    3. (Future) MITRE Mapper - Map to ATT&CK framework
    4. (Future) Report Generator - Create final reports
    """
    
    print("=" * 70)
    print("ATTACK SURFACE MAPPER")
    print("=" * 70)
    print()
    
    # Phase 1: Network Scanning
    print("[PHASE 1] Network Discovery")
    print("-" * 70)
    scanner = NetworkScanner(timeout=1.0, max_workers=100)
    scan_results = scanner.scan(target, ports)
    
    if not scan_results:
        print("\n[!] No open ports found. Exiting.")
        return
    
    print()
    
    # Phase 2: Service Enumeration (optional)
    if not skip_enumeration:
        print("[PHASE 2] Service Enumeration")
        print("-" * 70)
        
        # Convert scan results to (ip, port) tuples
        targets = [(r.ip, r.port) for r in scan_results]
        
        enumerator = ServiceEnumerator(use_cve_lookup=not skip_cve)
        service_results = enumerator.enumerate_multiple(targets)
        
        print()
        
        # Summary
        print("[SUMMARY]")
        print("-" * 70)
        print(f"Total hosts scanned: {len(set(r.ip for r in scan_results))}")
        print(f"Open ports found: {len(scan_results)}")
        print(f"Services enumerated: {len(service_results)}")
        
        if not skip_cve:
            total_cves = sum(len(s.vulnerabilities) for s in service_results)
            services_with_vulns = len([s for s in service_results if s.vulnerabilities])
            print(f"Services with vulnerabilities: {services_with_vulns}")
            print(f"Total CVEs discovered: {total_cves}")
            
            if total_cves > 0:
                print("\n[!] Vulnerabilities detected:")
                for service in service_results:
                    if service.vulnerabilities:
                        print(f"\n  {service.ip}:{service.port} - {service.product} {service.version}")
                        for vuln in service.vulnerabilities[:3]:  # Show top 3
                            print(f"    • {vuln.cve_id} [{vuln.severity}] CVSS: {vuln.cvss_score}")
        
        # Export results
        if output:
            enumerator.export_json(output)
    
    print()
    print("=" * 70)
    print("Scan complete!")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='Attack Surface Mapper - Discover and analyze security weaknesses',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan of common ports
  python main.py scan 192.168.1.100

  # Scan specific ports with full enumeration
  python main.py scan 192.168.1.100 -p 22,80,443,3306
  
  # Scan network range, skip CVE lookup for speed
  python main.py scan 192.168.1.0/24 --skip-cve
  
  # Full scan with report export
  python main.py scan 192.168.1.100 -o reports/scan_results.json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run attack surface scan')
    scan_parser.add_argument('target', help='Target IP or CIDR range')
    scan_parser.add_argument('-p', '--ports', help='Comma-separated ports (default: common ports)')
    scan_parser.add_argument('--skip-enum', action='store_true', 
                            help='Skip service enumeration (faster)')
    scan_parser.add_argument('--skip-cve', action='store_true',
                            help='Skip CVE lookup (faster)')
    scan_parser.add_argument('-o', '--output', help='Export results to JSON file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        # Parse ports
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        
        run_scan(
            target=args.target,
            ports=ports,
            skip_enumeration=args.skip_enum,
            skip_cve=args.skip_cve,
            output=args.output
        )


if __name__ == '__main__':
    main()