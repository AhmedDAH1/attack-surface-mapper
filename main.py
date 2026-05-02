#!/usr/bin/env python3
"""
Attack Surface Mapper
Main entry point that orchestrates all scanning and analysis modules.
"""

import argparse
import sys
from pathlib import Path
from src.scanners.network_scanner import NetworkScanner
from src.scanners.service_enumerator import ServiceEnumerator
from src.scanners.config_auditor import ConfigAuditor
from src.analyzers.mitre_mapper import MITREMapper
from src.reporters.html_reporter import HTMLReporter


def run_scan(target: str, ports: list = None, skip_enumeration: bool = False, 
             skip_cve: bool = False, output: str = None):
    """
    Run complete attack surface scan.
    
    Pipeline:
    1. Network Scanner - Discover open ports
    2. Service Enumerator - Identify versions and CVEs
    3. Configuration Auditor - Check for misconfigurations
    4. MITRE Mapper - Map to ATT&CK framework
    5. Report Generator - Create HTML and JSON reports
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
    mitre_findings = []
    service_results = []
    config_issues = []
    
    if not skip_enumeration:
        print("[PHASE 2] Service Enumeration")
        print("-" * 70)
        
        # Convert scan results to (ip, port) tuples
        targets = [(r.ip, r.port) for r in scan_results]
        
        enumerator = ServiceEnumerator(use_cve_lookup=not skip_cve)
        service_results = enumerator.enumerate_multiple(targets)
        
        print()
        
        # Phase 2.5: Configuration Audit
        print("[PHASE 2.5] Configuration Audit")
        print("-" * 70)
        
        # Prepare data for auditor (ip, port, service, banner)
        audit_targets = []
        for s in service_results:
            banner = None
            # Try to get banner from original scan results
            for scan_res in scan_results:
                if scan_res.ip == s.ip and scan_res.port == s.port:
                    banner = scan_res.banner
                    break
            audit_targets.append((s.ip, s.port, s.service, banner))
        
        auditor = ConfigAuditor()
        config_issues = auditor.audit_multiple(audit_targets)
        
        print()
        
        # Phase 3: MITRE ATT&CK Mapping
        print("[PHASE 3] MITRE ATT&CK Mapping")
        print("-" * 70)
        
        mapper = MITREMapper()
        mitre_findings = mapper.map_findings(service_results)
        
        print()
        
        # Phase 4: Report Generation
        print("[PHASE 4] Report Generation")
        print("-" * 70)
        
        # Generate output filename if not provided
        if not output:
            timestamp = Path(f"reports/scan_{target.replace('/', '_')}").stem
            output_base = f"reports/attack_surface_{timestamp}"
        else:
            output_base = Path(output).stem
            output_base = f"reports/{output_base}"
        
        # Generate both JSON and HTML reports
        json_file = f"{output_base}.json"
        html_file = f"{output_base}.html"
        
        # JSON export (for automation)
        mapper.export_json(json_file)
        
        # HTML report (for viewing)
        reporter = HTMLReporter()
        reporter.generate_report(
            network_results=scan_results,
            service_results=service_results,
            mitre_findings=mitre_findings,
            config_issues=config_issues,
            output_file=html_file
        )
        
        print()
        
        # Summary
        print("[SUMMARY]")
        print("=" * 70)
        print(f"Total hosts scanned: {len(set(r.ip for r in scan_results))}")
        print(f"Open ports found: {len(scan_results)}")
        print(f"Services enumerated: {len(service_results)}")
        
        # Configuration audit stats
        if config_issues:
            config_summary = auditor.get_summary()
            print(f"\nConfiguration Issues: {config_summary['total_issues']}")
            print(f"  Critical: {config_summary['by_severity']['critical']}")
            print(f"  High: {config_summary['by_severity']['high']}")
            print(f"  Medium: {config_summary['by_severity']['medium']}")
            print(f"  Low: {config_summary['by_severity']['low']}")
        
        # MITRE stats
        if mitre_findings:
            attack_summary = mapper.get_attack_summary()
            print(f"\nMITRE ATT&CK Analysis:")
            print(f"  Techniques identified: {attack_summary['unique_techniques']}")
            print(f"  Tactics covered: {len(attack_summary['tactics_covered'])}")
            
            # Risk breakdown
            risk_dist = attack_summary['risk_distribution']
            print(f"\nRisk Distribution:")
            print(f"  Critical (≥7.0): {risk_dist['critical']}")
            print(f"  High (5.0-6.9): {risk_dist['high']}")
            print(f"  Medium (3.0-4.9): {risk_dist['medium']}")
            print(f"  Low (<3.0): {risk_dist['low']}")
        
        if not skip_cve:
            total_cves = sum(len(s.vulnerabilities) for s in service_results)
            services_with_vulns = len([s for s in service_results if s.vulnerabilities])
            print(f"\nVulnerability Summary:")
            print(f"  Services with CVEs: {services_with_vulns}")
            print(f"  Total CVEs found: {total_cves}")
            
            if total_cves > 0:
                print("\n[!] Top Vulnerabilities:")
                for service in service_results:
                    if service.vulnerabilities:
                        print(f"\n  {service.ip}:{service.port} - {service.product} {service.version}")
                        for vuln in service.vulnerabilities[:2]:
                            print(f"    • {vuln.cve_id} [{vuln.severity}] CVSS: {vuln.cvss_score}")
        
        print(f"\n📊 Reports Generated:")
        print(f"  • JSON: {json_file}")
        print(f"  • HTML: {html_file}")
        print(f"\n💡 Open the HTML report in your browser to view the interactive dashboard!")
    
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
  # Quick scan of common ports (generates HTML + JSON reports)
  python main.py scan 192.168.1.100

  # Scan specific ports with full analysis
  python main.py scan 192.168.1.100 -p 22,80,443,3306
  
  # Scan network range, skip CVE lookup for speed
  python main.py scan 192.168.1.0/24 --skip-cve
  
  # Full scan with custom report name
  python main.py scan 192.168.1.100 -o my_company_scan
  
  # Fast scan (network discovery only)
  python main.py scan 192.168.1.0/24 --skip-enum
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
    scan_parser.add_argument('-o', '--output', help='Report base name (auto-generates .json and .html)')
    
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
