#!/usr/bin/env python3
"""
Attack Surface Mapper - Web UI
Flask web application for interactive security scanning.
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import sys
import os
import json
import threading
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanners.network_scanner import NetworkScanner
from src.scanners.service_enumerator import ServiceEnumerator
from src.scanners.config_auditor import ConfigAuditor
from src.analyzers.mitre_mapper import MITREMapper
from src.analyzers.compliance_checker import ComplianceChecker
from src.reporters.html_reporter import HTMLReporter
from src.reporters.pdf_reporter import PDFReporter
from src.reporters.csv_reporter import CSVReporter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'attack-surface-mapper-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store scan history
scan_history = []
current_scan = None


def emit_progress(message, severity='info'):
    """Emit progress update to frontend"""
    socketio.emit('scan_progress', {
        'message': message,
        'severity': severity,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })


def run_scan_background(target, ports, skip_cve):
    """Run scan in background thread"""
    global current_scan
    
    try:
        emit_progress(f"🎯 Starting scan of {target}", 'info')
        
        # Initialize scan record
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        current_scan = {
            'id': scan_id,
            'target': target,
            'start_time': datetime.now().isoformat(),
            'status': 'running',
            'ports_scanned': 0,
            'ports_open': 0,
            'services_found': 0,
            'vulnerabilities': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'compliance_score': 100
        }
        
        # Phase 1: Network Scanning
        emit_progress("📡 Phase 1: Network Discovery", 'info')
        scanner = NetworkScanner(timeout=1.0, max_workers=100)
        scan_results = scanner.scan(target, ports)
        
        if not scan_results:
            emit_progress("❌ No open ports found", 'warning')
            current_scan['status'] = 'completed'
            current_scan['end_time'] = datetime.now().isoformat()
            scan_history.append(current_scan)
            socketio.emit('scan_complete', current_scan)
            return
        
        current_scan['ports_scanned'] = len(scan_results)
        current_scan['ports_open'] = len(scan_results)
        
        for result in scan_results:
            emit_progress(f"✅ Found port {result.port} ({result.service})", 'success')
        
        socketio.emit('scan_stats', current_scan)
        
        # Phase 2: Service Enumeration
        emit_progress("🔍 Phase 2: Service Enumeration", 'info')
        targets = [(r.ip, r.port) for r in scan_results]
        enumerator = ServiceEnumerator(use_cve_lookup=not skip_cve)
        service_results = enumerator.enumerate_multiple(targets)
        
        current_scan['services_found'] = len(service_results)
        
        # Count vulnerabilities
        total_vulns = sum(len(s.vulnerabilities) for s in service_results)
        current_scan['vulnerabilities'] = total_vulns
        
        for service in service_results:
            emit_progress(f"🔎 {service.ip}:{service.port} - {service.product} {service.version}", 'info')
            if service.vulnerabilities:
                emit_progress(f"⚠️  Found {len(service.vulnerabilities)} CVE(s)", 'warning')
        
        socketio.emit('scan_stats', current_scan)
        
        # Phase 2.5: Configuration Audit
        emit_progress("⚙️  Phase 2.5: Configuration Audit", 'info')
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
        
        critical_count = len([c for c in config_issues if c.severity == 'CRITICAL'])
        high_count = len([c for c in config_issues if c.severity == 'HIGH'])
        
        current_scan['critical_issues'] = critical_count
        current_scan['high_issues'] = high_count
        
        for issue in config_issues:
            severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
            emit_progress(
                f"{severity_emoji.get(issue.severity, '⚪')} {issue.ip}:{issue.port} - {issue.title}",
                issue.severity.lower()
            )
        
        socketio.emit('scan_stats', current_scan)
        
        # Phase 3: MITRE Mapping
        emit_progress("🎯 Phase 3: MITRE ATT&CK Mapping", 'info')
        mapper = MITREMapper()
        mitre_findings = mapper.map_findings(service_results)
        
        emit_progress(f"📊 Mapped {len(mitre_findings)} findings to MITRE ATT&CK", 'info')
        
        # Phase 3.7: Compliance
        emit_progress("📋 Phase 3.7: Compliance Analysis", 'info')
        compliance = ComplianceChecker()
        compliance_violations = compliance.check_compliance(
            config_issues=config_issues,
            mitre_findings=mitre_findings,
            service_results=service_results
        )
        
        compliance_summary = compliance.get_summary()
        current_scan['compliance_score'] = compliance_summary['compliance_score']
        
        emit_progress(
            f"📊 Compliance Score: {compliance_summary['compliance_score']}/100",
            'info' if compliance_summary['compliance_score'] >= 70 else 'warning'
        )
        
        socketio.emit('scan_stats', current_scan)
        
        # Phase 4: Generate Reports
        emit_progress("📄 Phase 4: Generating Reports", 'info')
        
        output_base = f"reports/web_scan_{scan_id}"
        
        json_file = f"{output_base}.json"
        html_file = f"{output_base}.html"
        pdf_file = f"{output_base}.pdf"
        csv_file = f"{output_base}.csv"
        
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
        
        # Store report paths
        current_scan['reports'] = {
            'json': json_file,
            'html': html_file,
            'pdf': pdf_file,
            'csv': csv_file
        }
        
        # Complete scan
        current_scan['status'] = 'completed'
        current_scan['end_time'] = datetime.now().isoformat()
        
        # Store detailed results
        current_scan['findings'] = {
            'ports': [{'ip': r.ip, 'port': r.port, 'service': r.service} for r in scan_results],
            'services': [{'ip': s.ip, 'port': s.port, 'product': s.product, 'version': s.version} for s in service_results],
            'config_issues': [{'ip': c.ip, 'port': c.port, 'severity': c.severity, 'title': c.title} for c in config_issues],
            'compliance': compliance_summary
        }
        
        emit_progress("✅ Scan completed successfully!", 'success')
        
        # Add to history
        scan_history.append(current_scan.copy())
        
        # Emit completion
        socketio.emit('scan_complete', current_scan)
        
    except Exception as e:
        emit_progress(f"❌ Error: {str(e)}", 'error')
        if current_scan:
            current_scan['status'] = 'failed'
            current_scan['error'] = str(e)
            current_scan['end_time'] = datetime.now().isoformat()
            scan_history.append(current_scan)
            socketio.emit('scan_complete', current_scan)


@app.route('/')
def index():
    """Render main dashboard"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    target = data.get('target')
    ports_str = data.get('ports', '')
    skip_cve = data.get('skip_cve', False)
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Parse ports
    ports = None
    if ports_str:
        try:
            ports = [int(p.strip()) for p in ports_str.split(',')]
        except:
            return jsonify({'error': 'Invalid port format'}), 400
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan_background, args=(target, ports, skip_cve))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started', 'message': 'Scan initiated'})


@app.route('/api/history')
def get_history():
    """Get scan history"""
    return jsonify(scan_history)


@app.route('/api/current')
def get_current():
    """Get current scan status"""
    if current_scan:
        return jsonify(current_scan)
    return jsonify({'status': 'idle'})


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'message': 'Connected to Attack Surface Mapper'})

@app.route('/reports/<filename>')
def download_report(filename):
    """Download report file"""
    from flask import send_file
    filepath = os.path.join('..', 'reports', filename)
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    print("=" * 70)
    print("ATTACK SURFACE MAPPER - WEB UI")
    print("=" * 70)
    print()
    print("🌐 Server starting at: http://localhost:5001")
    print("📊 Open your browser and navigate to the URL above")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 70)
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=False)
