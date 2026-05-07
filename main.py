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
from src.analyzers.compliance_checker import ComplianceChecker
from src.reporters.html_reporter import HTMLReporter
from src.reporters.pdf_reporter import PDFReporter
from src.reporters.csv_reporter import CSVReporter
from src.integrations.slack_notifier import SlackNotifier
from src.integrations.shodan_checker import ShodanChecker
from src.integrations.virustotal_checker import VirusTotalChecker
from src.core.continuous_monitor import ContinuousMonitor


def run_scan(target: str, ports: list = None, skip_enumeration: bool = False, 
             skip_cve: bool = False, output: str = None, slack_webhook: str = None,
             shodan_key: str = None, vt_key: str = None):
    """
    Run complete attack surface scan with compliance checking.
    
    Pipeline:
    1. Network Scanner - Discover open ports
    2. Service Enumerator - Identify versions and CVEs
    3. Configuration Auditor - Check for misconfigurations
    4. MITRE Mapper - Map to ATT&CK framework
    5. Compliance Checker - PCI-DSS, NIST, CIS analysis
    6. Threat Intelligence - Shodan & VirusTotal checks
    7. Report Generator - Create JSON, HTML, PDF, CSV reports
    8. Slack Notifier - Send alerts
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
    
    # Initialize variables
    mitre_findings = []
    service_results = []
    config_issues = []
    compliance_violations = []
    shodan_results = []
    vt_results = []
    
    if not skip_enumeration:
        print("[PHASE 2] Service Enumeration")
        print("-" * 70)
        
        targets = [(r.ip, r.port) for r in scan_results]
        
        enumerator = ServiceEnumerator(use_cve_lookup=not skip_cve)
        service_results = enumerator.enumerate_multiple(targets)
        
        print()
        
        # Phase 2.5: Configuration Audit
        print("[PHASE 2.5] Configuration Audit")
        print("-" * 70)
        
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
        
        print()
        
        # Phase 3: MITRE ATT&CK Mapping
        print("[PHASE 3] MITRE ATT&CK Mapping")
        print("-" * 70)
        
        mapper = MITREMapper()
        mitre_findings = mapper.map_findings(service_results)
        
        print()
        
        # Phase 3.7: Compliance Checking
        print("[PHASE 3.7] Compliance Framework Analysis")
        print("-" * 70)
        
        compliance = ComplianceChecker()
        compliance_violations = compliance.check_compliance(
            config_issues=config_issues,
            mitre_findings=mitre_findings,
            service_results=service_results
        )
        
        compliance_summary = compliance.get_summary()
        print(f"\n📊 Compliance Score: {compliance_summary['compliance_score']}/100")
        if compliance_summary['total_violations'] > 0:
            print(f"⚠️  Found {compliance_summary['total_violations']} compliance violation(s)")
        else:
            print(f"✅ No compliance violations detected")
        
        print()
        
        # Phase 3.5: Threat Intelligence
        if shodan_key or vt_key:
            print("[PHASE 3.5] Threat Intelligence")
            print("-" * 70)
            
            if shodan_key:
                try:
                    shodan = ShodanChecker(shodan_key)
                    targets_for_shodan = [(r.ip, r.port) for r in scan_results]
                    shodan_results = shodan.check_multiple(targets_for_shodan)
                    
                    shodan_summary = shodan.get_summary()
                    if shodan_summary['globally_exposed'] > 0:
                        print(f"\n[!] SHODAN: {shodan_summary['globally_exposed']} IP(s) exposed globally!")
                except Exception as e:
                    print(f"[!] Shodan check failed: {e}")
            
            if vt_key:
                try:
                    vt = VirusTotalChecker(vt_key)
                    unique_ips = list(set(r.ip for r in scan_results))
                    vt_results = vt.check_multiple_ips(unique_ips)
                    
                    vt_summary = vt.get_summary()
                    if vt_summary['malicious'] > 0:
                        print(f"\n[!] VIRUSTOTAL: {vt_summary['malicious']} malicious IP(s) detected!")
                    
                    vt.close()
                except Exception as e:
                    print(f"[!] VirusTotal check failed: {e}")
            
            print()
        
        # Phase 4: Report Generation
        print("[PHASE 4] Report Generation")
        print("-" * 70)
        
        if not output:
            timestamp = Path(f"reports/scan_{target.replace('/', '_')}").stem
            output_base = f"reports/attack_surface_{timestamp}"
        else:
            output_base = Path(output).stem
            output_base = f"reports/{output_base}"
        
        json_file = f"{output_base}.json"
        html_file = f"{output_base}.html"
        pdf_file = f"{output_base}.pdf"
        csv_file = f"{output_base}.csv"
        
        # Generate reports
        mapper.export_json(json_file)
        
        reporter = HTMLReporter()
        reporter.generate_report(
            network_results=scan_results,
            service_results=service_results,
            mitre_findings=mitre_findings,
            config_issues=config_issues,
            output_file=html_file
        )
        
        pdf_reporter = PDFReporter()
        pdf_reporter.generate_report(
            network_results=scan_results,
            service_results=service_results,
            mitre_findings=mitre_findings,
            config_issues=config_issues,
            output_file=pdf_file
        )
        
        csv_reporter = CSVReporter()
        csv_reporter.generate_report(
            network_results=scan_results,
            service_results=service_results,
            mitre_findings=mitre_findings,
            config_issues=config_issues,
            output_file=csv_file
        )
        
        print()
        
        # Summary
        print("[SUMMARY]")
        print("=" * 70)
        print(f"Total hosts scanned: {len(set(r.ip for r in scan_results))}")
        print(f"Open ports found: {len(scan_results)}")
        print(f"Services enumerated: {len(service_results)}")
        
        # Configuration audit stats
        config_summary = None
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
        
        # Compliance stats
        if compliance_violations:
            print(f"\nCompliance Analysis:")
            print(f"  Overall Score: {compliance_summary['compliance_score']}/100")
            print(f"  Total Violations: {compliance_summary['total_violations']}")
            print(f"  By Severity - Critical: {compliance_summary['by_severity']['CRITICAL']}, "
                  f"High: {compliance_summary['by_severity']['HIGH']}, "
                  f"Medium: {compliance_summary['by_severity']['MEDIUM']}")
            for framework, count in compliance_summary['by_framework'].items():
                print(f"    {framework}: {count} violation(s)")
        
        # Threat Intelligence stats
        if shodan_key or vt_key:
            print(f"\nThreat Intelligence:")
            if shodan_key and shodan_results:
                shodan_summary = shodan.get_summary()
                print(f"  Shodan - Globally Exposed: {shodan_summary['globally_exposed']}/{shodan_summary['total_ips_checked']}")
            if vt_key and vt_results:
                vt_summary = vt.get_summary()
                print(f"  VirusTotal - Malicious IPs: {vt_summary['malicious']}/{vt_summary['total_checked']}")
        
        print(f"\n📊 Reports Generated:")
        print(f"  • JSON: {json_file}")
        print(f"  • HTML: {html_file}")
        print(f"  • PDF: {pdf_file}")
        print(f"  • CSV: {csv_file}")
        
        # Slack notification
        if slack_webhook:
            print(f"\n📢 Sending Slack notification...")
            notifier = SlackNotifier(slack_webhook)
            notifier.send_scan_complete(
                target=target,
                findings_count=len(mitre_findings),
                critical_count=config_summary['by_severity']['critical'] if config_summary else 0,
                high_count=config_summary['by_severity']['high'] if config_summary else 0
            )
        
        # Print executive summary if compliance violations
        if compliance_violations and len(compliance_violations) > 0:
            print(f"\n{compliance.generate_executive_summary()}")
    
    print()
    print("=" * 70)
    print("Scan complete!")
    print("=" * 70)


def run_monitor(target: str, interval: int, ports: list = None, 
                skip_cve: bool = False, num_scans: int = None, slack_webhook: str = None):
    """Run continuous monitoring mode"""
    
    print("=" * 70)
    print("CONTINUOUS MONITORING MODE")
    print("=" * 70)
    print(f"Target: {target}")
    print(f"Interval: {interval} minutes")
    if slack_webhook:
        print(f"Slack alerts: ENABLED")
    print(f"Press Ctrl+C to stop monitoring")
    print("=" * 70)
    print()
    
    monitor = ContinuousMonitor(
        target=target,
        interval_minutes=interval,
        alert_on_new_ports=True,
        alert_on_new_vulns=True
    )
    
    notifier = SlackNotifier(slack_webhook) if slack_webhook else None
    scan_count = 0
    
    try:
        while True:
            scan_count += 1
            print(f"\n{'='*70}")
            print(f"SCAN #{scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*70}\n")
            
            scanner = NetworkScanner(timeout=1.0, max_workers=100)
            scan_results = scanner.scan(target, ports)
            
            if scan_results:
                targets = [(r.ip, r.port) for r in scan_results]
                enumerator = ServiceEnumerator(use_cve_lookup=not skip_cve)
                service_results = enumerator.enumerate_multiple(targets)
                
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
                
                import sys
                from io import StringIO
                old_stdout = sys.stdout
                sys.stdout = StringIO()
                
                mapper = MITREMapper()
                mitre_findings = mapper.map_findings(service_results)
                
                sys.stdout = old_stdout
            else:
                service_results = []
                config_issues = []
                mitre_findings = []
                print("\n[!] No open ports found in this scan")
            
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
                
                if notifier:
                    notifier.send_monitoring_change(target, changes)
            else:
                print("\n✅ No changes detected - attack surface stable")
            
            summary = monitor.get_summary()
            print(f"\n📊 MONITORING SUMMARY:")
            print(f"  Total scans: {summary['total_scans']}")
            print(f"  Total alerts: {summary['total_alerts']}")
            if summary.get('current_state'):
                print(f"  Current state: {summary['current_state']['open_ports']} ports, "
                      f"{summary['current_state']['vulnerabilities']} CVEs, "
                      f"{summary['current_state']['critical_issues']} critical issues")
            
            if num_scans and scan_count >= num_scans:
                print(f"\n✅ Completed {num_scans} scan(s)")
                break
            
            if not num_scans or scan_count < num_scans:
                print(f"\n⏳ Next scan in {interval} minute(s)...")
                print(f"   Press Ctrl+C to stop monitoring\n")
                time.sleep(interval * 60)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Monitoring stopped by user")
    
    print(f"\n{monitor.generate_diff_report()}")
    print("\n✅ Monitoring session complete")


def main():
    parser = argparse.ArgumentParser(
        description='Attack Surface Mapper - Enterprise Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with compliance checking
  python main.py scan 192.168.1.100

  # Full enterprise scan
  python main.py scan 192.168.1.100 \\
    --shodan-key YOUR_KEY \\
    --vt-key YOUR_KEY \\
    --slack-webhook https://hooks.slack.com/... \\
    -o enterprise_scan

  # Continuous monitoring
  python main.py monitor 192.168.1.0/24 -i 60 --slack-webhook https://hooks.slack.com/...
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    scan_parser = subparsers.add_parser('scan', help='Run attack surface scan')
    scan_parser.add_argument('target', help='Target IP or CIDR range')
    scan_parser.add_argument('-p', '--ports', help='Comma-separated ports')
    scan_parser.add_argument('--skip-enum', action='store_true', help='Skip enumeration')
    scan_parser.add_argument('--skip-cve', action='store_true', help='Skip CVE lookup')
    scan_parser.add_argument('-o', '--output', help='Report base name')
    scan_parser.add_argument('--slack-webhook', help='Slack webhook URL')
    scan_parser.add_argument('--shodan-key', help='Shodan API key')
    scan_parser.add_argument('--vt-key', help='VirusTotal API key')
    
    monitor_parser = subparsers.add_parser('monitor', help='Continuous monitoring')
    monitor_parser.add_argument('target', help='Target to monitor')
    monitor_parser.add_argument('-i', '--interval', type=int, default=60, help='Interval (minutes)')
    monitor_parser.add_argument('-p', '--ports', help='Ports to monitor')
    monitor_parser.add_argument('--skip-cve', action='store_true', help='Skip CVE lookup')
    monitor_parser.add_argument('-n', '--num-scans', type=int, help='Number of scans')
    monitor_parser.add_argument('--slack-webhook', help='Slack webhook URL')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        
        run_scan(
            target=args.target,
            ports=ports,
            skip_enumeration=args.skip_enum,
            skip_cve=args.skip_cve,
            output=args.output,
            slack_webhook=args.slack_webhook,
            shodan_key=args.shodan_key,
            vt_key=args.vt_key
        )
    
    elif args.command == 'monitor':
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        
        run_monitor(
            target=args.target,
            interval=args.interval,
            ports=ports,
            skip_cve=args.skip_cve,
            num_scans=args.num_scans,
            slack_webhook=args.slack_webhook
        )


if __name__ == '__main__':
    main()
