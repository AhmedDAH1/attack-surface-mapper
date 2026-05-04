#!/usr/bin/env python3
"""
Attack Surface Mapper
Main entry point that orchestrates all scanning and analysis modules.
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path
from src.scanners.network_scanner import NetworkScanner
from src.scanners.service_enumerator import ServiceEnumerator
from src.scanners.config_auditor import ConfigAuditor
from src.analyzers.mitre_mapper import MITREMapper
from src.reporters.html_reporter import HTMLReporter
from src.reporters.pdf_reporter import PDFReporter
from src.core.continuous_monitor import ContinuousMonitor


def run_scan(target: str, ports: list = None, skip_enumeration: bool = False, 
             skip_cve: bool = False, output: str = None):
    """
    Run complete attack surface scan.
    
    Pipeline:
    1. Network Scanner - Discover open ports
    2. Service Enumerator - Identify versions and CVEs
    3. Configuration Auditor - Check for misconfigurations
    4. MITRE Mapper - Map to ATT&CK framework
    5. Report Generator - Create HTML, PDF, and JSON reports
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
        
        # Generate JSON, HTML, and PDF reports
        json_file = f"{output_base}.json"
        html_file = f"{output_base}.html"
        pdf_file = f"{output_base}.pdf"
        
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
        
        # PDF report (for distribution)
        pdf_reporter = PDFReporter()
        pdf_reporter.generate_report(
            network_results=scan_results,
            service_results=service_results,
            mitre_findings=mitre_findings,
            config_issues=config_issues,
            output_file=pdf_file
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
        print(f"  • PDF: {pdf_file}")
        print(f"\n💡 Open the HTML report in your browser to view the interactive dashboard!")
        print(f"   Open the PDF report for a professional security assessment document!")
    
    print()
    print("=" * 70)
    print("Scan complete!")
    print("=" * 70)


def run_monitor(target: str, interval: int, ports: list = None, 
                skip_cve: bool = False, num_scans: int = None):
    """
    Run continuous monitoring mode.
    
    Args:
        target: Target to monitor
        interval: Scan interval in minutes
        ports: Ports to scan
        skip_cve: Skip CVE lookup
        num_scans: Number of scans (None = infinite)
    """
    
    print("=" * 70)
    print("CONTINUOUS MONITORING MODE")
    print("=" * 70)
    print(f"Target: {target}")
    print(f"Interval: {interval} minutes")
    print(f"Press Ctrl+C to stop monitoring")
    print("=" * 70)
    print()
    
    # Initialize monitor
    monitor = ContinuousMonitor(
        target=target,
        interval_minutes=interval,
        alert_on_new_ports=True,
        alert_on_new_vulns=True
    )
    
    scan_count = 0
    
    try:
        while True:
            scan_count += 1
            print(f"\n{'='*70}")
            print(f"SCAN #{scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*70}\n")
            
            # Run full scan pipeline
            scanner = NetworkScanner(timeout=1.0, max_workers=100)
            scan_results = scanner.scan(target, ports)
            
            # Always run change detection (even if no ports found)
            if scan_results:
                # Service enumeration
                targets = [(r.ip, r.port) for r in scan_results]
                enumerator = ServiceEnumerator(use_cve_lookup=not skip_cve)
                service_results = enumerator.enumerate_multiple(targets)
                
                # Configuration audit
                audit_targets = []
                for s in service_results:
                    banner = None
                    for scan_res in scan_results:
                        if scan_res.ip == s.ip and scan_res.port == s.port:
                            banner = scan_res.banner
                            break
                    audit_targets.append((s.ip, s.port, s.service, banner))
                
                auditor = ConfigAuditor()
                config_issues = auditor.audit_multiple(audit_targets)
                
                # MITRE mapping (suppress output)
                import sys
                from io import StringIO
                old_stdout = sys.stdout
                sys.stdout = StringIO()
                
                mapper = MITREMapper()
                mitre_findings = mapper.map_findings(service_results)
                
                sys.stdout = old_stdout
            else:
                # No ports found - use empty results
                service_results = []
                config_issues = []
                mitre_findings = []
                print("\n[!] No open ports found in this scan")
            
            # Always process changes (detect closed ports too)
            print(f"\n{'='*70}")
            print("CHANGE DETECTION")
            print(f"{'='*70}")
            changes = monitor.process_scan_results(
                scan_results if scan_results else [], 
                service_results, 
                config_issues, 
                mitre_findings
            )
            
            if changes:
                print(f"\n⚠️  {len(changes)} CHANGE(S) DETECTED:")
                for change in changes:
                    print(f"  [{change.severity}] {change.description}")
            else:
                print("\n✅ No changes detected - attack surface stable")
            
            # Show summary
            summary = monitor.get_summary()
            print(f"\n📊 MONITORING SUMMARY:")
            print(f"  Total scans: {summary['total_scans']}")
            print(f"  Total alerts: {summary['total_alerts']}")
            if summary.get('current_state'):
                print(f"  Current state: {summary['current_state']['open_ports']} ports, "
                      f"{summary['current_state']['vulnerabilities']} CVEs, "
                      f"{summary['current_state']['critical_issues']} critical issues")
            
            # Check if we've hit scan limit
            if num_scans and scan_count >= num_scans:
                print(f"\n✅ Completed {num_scans} scan(s)")
                break
            
            # Wait for next scan
            if not num_scans or scan_count < num_scans:
                print(f"\n⏳ Next scan in {interval} minute(s)...")
                print(f"   Press Ctrl+C to stop monitoring\n")
                time.sleep(interval * 60)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Monitoring stopped by user")
    
    # Generate final diff report
    print(f"\n{monitor.generate_diff_report()}")
    
    print("\n✅ Monitoring session complete")


def main():
    parser = argparse.ArgumentParser(
        description='Attack Surface Mapper - Discover and analyze security weaknesses',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single scan (generates JSON, HTML, and PDF reports)
  python main.py scan 192.168.1.100

  # Scan specific ports
  python main.py scan 192.168.1.100 -p 22,80,443,3306

  # Continuous monitoring (scan every 60 minutes)
  python main.py monitor 192.168.1.100 --interval 60

  # Monitor with 3 scans then stop
  python main.py monitor 127.0.0.1 -i 5 -n 3
  
  # Fast scan (skip enumeration)
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
    scan_parser.add_argument('-o', '--output', help='Report base name (auto-generates .json, .html, .pdf)')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Continuous monitoring mode')
    monitor_parser.add_argument('target', help='Target IP or CIDR range to monitor')
    monitor_parser.add_argument('-i', '--interval', type=int, default=60,
                               help='Scan interval in minutes (default: 60)')
    monitor_parser.add_argument('-p', '--ports', help='Comma-separated ports to monitor')
    monitor_parser.add_argument('--skip-cve', action='store_true',
                               help='Skip CVE lookup (faster scans)')
    monitor_parser.add_argument('-n', '--num-scans', type=int,
                               help='Number of scans to run (default: infinite)')
    
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
    
    elif args.command == 'monitor':
        # Parse ports
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        
        run_monitor(
            target=args.target,
            interval=args.interval,
            ports=ports,
            skip_cve=args.skip_cve,
            num_scans=args.num_scans
        )


if __name__ == '__main__':
    main()
