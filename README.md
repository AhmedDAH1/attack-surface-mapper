# Attack Surface Mapper

A Python-based enterprise security assessment tool that discovers network vulnerabilities, maps them to MITRE ATT&CK techniques, checks compliance against major frameworks, and provides beautiful real-time dashboards.

Built to automate security assessments while providing actionable insights through multiple interfaces - CLI, terminal dashboard, and web UI.

## Why I Built This

After running countless manual security scans, I got tired of:
- Spending hours on repetitive port scanning and service enumeration
- Manually mapping findings to MITRE ATT&CK
- Writing the same compliance reports over and over
- Not knowing when my attack surface changed
- Having no visual way to present findings to clients

So I automated it. This tool does what I used to do manually - discover services, find misconfigurations, check compliance, and present everything beautifully in real-time.

## What It Does

**Scanning**
- Finds open ports and running services (multi-threaded, so it's fast)
- Identifies exact software versions
- Grabs service banners for fingerprinting
- Detects insecure configurations (default credentials, weak SSL/TLS, cleartext protocols)

**Analysis**
- Correlates findings with CVE database for known vulnerabilities
- Maps everything to MITRE ATT&CK tactics and techniques
- Checks compliance against PCI-DSS, NIST CSF, and CIS Controls
- Calculates risk scores based on severity and exploitability

**Threat Intelligence**
- Checks if your services are exposed on Shodan (are you on the public internet?)
- Validates IPs against VirusTotal for malicious activity
- Identifies services visible globally vs locally

**Monitoring**
- Watches your attack surface continuously
- Detects new ports, services, or vulnerabilities as they appear
- Sends Slack alerts when critical changes happen
- Tracks trends over time with diff reports

**Reporting**
- JSON for automation and APIs
- Interactive HTML dashboards you can actually navigate
- Professional PDF reports for clients or management
- CSV exports for Excel analysis

**Visualization**
- Live terminal dashboard with ASCII art and real-time updates
- Web-based UI with charts, graphs, and live scanning
- Beautiful gradient design with modern responsive layout

## Quick Start

```bash
# Clone the repo
git clone https://github.com/AhmedDAH1/attack-surface-mapper.git
cd attack-surface-mapper

# Install dependencies
pip install -r requirements.txt
brew install nmap  # macOS
# or: sudo apt-get install nmap  # Linux

# Run a basic scan
python main.py scan 192.168.1.100

# Use the live dashboard (looks amazing!)
python main.py scan 192.168.1.100 --dashboard

# Start the web interface
python3 web/app.py
# Then open: http://localhost:5001
```

That's it. No complex setup, no configuration files to edit.

## Real-World Usage

**Command-Line Scanning**
```bash
# Basic scan
python main.py scan 192.168.1.100

# Scan with all features
python main.py scan 192.168.1.100 \
  --dashboard \
  --shodan-key YOUR_KEY \
  --vt-key YOUR_KEY \
  --slack-webhook https://hooks.slack.com/... \
  -o client_assessment

# You get 4 reports automatically:
# - client_assessment.json (for automation)
# - client_assessment.html (interactive dashboard)
# - client_assessment.pdf (professional report)
# - client_assessment.csv (for spreadsheets)
```

**Live Terminal Dashboard**
```bash
# Beautiful ASCII dashboard with real-time updates
python main.py scan 192.168.1.100 --dashboard

# Watch the magic:
# - ASCII art banner
# - Live statistics with emojis
# - Threat level meter
# - Recent findings stream
# - Elapsed time tracker
```

**Web Interface**
```bash
# Start the web server
python3 web/app.py

# Open browser to: http://localhost:5001

# Features:
# - Point-and-click scanning
# - Real-time progress updates
# - Interactive charts (Chart.js)
# - Download reports in all formats
# - Beautiful gradient design
# - Perfect for client demos
```

**Continuous Monitoring**
```bash
# Monitor your infrastructure every hour
python main.py monitor 192.168.1.0/24 \
  --interval 60 \
  --slack-webhook https://hooks.slack.com/...

# It'll alert you on Slack when:
# - New ports open
# - Services change versions
# - New vulnerabilities appear
# - Critical misconfigurations detected
```

**Compliance Checking**
```bash
# See if you meet PCI-DSS, NIST, or CIS requirements
python main.py scan 192.168.1.100

# Output includes:
# - Compliance score (0-100)
# - Specific violations by framework
# - Remediation steps
# - Executive summary
```

## Interfaces

**1. Command-Line Interface**
- Traditional CLI output
- Perfect for scripting and automation
- All features available via flags
- Generates all 4 report formats

**2. Live Terminal Dashboard**
- Beautiful ASCII art interface
- Real-time statistics with emoji indicators
- Threat level visualization
- Activity stream
- Built with Rich library

**3. Web Dashboard**
- Modern gradient design
- Real-time WebSocket updates
- Interactive charts and graphs
- Download reports directly
- Mobile-responsive
- Perfect for demos and presentations

## What the Output Looks Like

**Terminal Dashboard**

╔═══════════════════════════════════════════════════════════╗
║     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗   ║
║         SURFACE MAPPER  -  Real-Time Assessment          ║
╚═══════════════════════════════════════════════════════════╝
Live Statistics:
Ports Scanned:     5          🟡
Open Ports:        3          🟡
Services Found:    3
Vulnerabilities:   2          🔴
Critical Issues:   0          🟢
High Issues:       1          🟡
Compliance Score:  70/100     🟡
Threat Assessment: MODERATE ⚠️

**Web Dashboard**
- Beautiful gradient background (purple to blue)
- Real-time stat cards updating live
- Doughnut chart showing risk distribution
- Bar chart showing compliance by framework
- Download buttons for all report formats
- Live activity log with color-coded entries

**HTML Report** (interactive, actually useful)
- Executive summary with key metrics
- Risk distribution charts
- Configuration issues with remediation
- MITRE technique breakdown
- Compliance violations by framework

**PDF Report** (client-ready)
- Professional cover page
- Executive summary
- Detailed findings tables
- Compliance analysis
- Actionable recommendations

## API Keys (All Free Tier)

**Shodan** (optional, checks global exposure)
- Sign up: https://account.shodan.io/register
- Free tier: 100 queries/month
- Use: `--shodan-key YOUR_KEY`

**VirusTotal** (optional, checks IP reputation)
- Sign up: https://www.virustotal.com/gui/join-us
- Free tier: 500 requests/day
- Use: `--vt-key YOUR_KEY`

**Slack** (optional, for alerts)
- Create webhook: https://api.slack.com/messaging/webhooks
- Use: `--slack-webhook https://hooks.slack.com/...`

You don't need any of these to use the tool. They just add extra intelligence.

## Command Reference

```bash
# CLI Scanning
python main.py scan <target>                    # Basic scan
python main.py scan <target> --dashboard        # With live UI
python main.py scan <target> -p 22,80,443       # Specific ports
python main.py scan <target> --skip-cve         # Skip CVE lookup (faster)
python main.py scan <target> -o my_scan         # Custom output name

# Full enterprise scan
python main.py scan <target> \
  --dashboard \
  --shodan-key KEY \
  --vt-key KEY \
  --slack-webhook URL \
  -o enterprise_scan

# Continuous monitoring
python main.py monitor <target> -i 60           # Every 60 minutes
python main.py monitor <target> -i 30 -n 5      # 5 scans then stop

# Web Interface
python3 web/app.py                              # Start web server
# Then open: http://localhost:5001
```

## Project Structure
attack-surface-mapper/
├── src/
│   ├── scanners/           # Port scanning, enumeration, config auditing
│   ├── analyzers/          # MITRE mapping, compliance checking
│   ├── reporters/          # JSON, HTML, PDF, CSV generation
│   ├── integrations/       # Shodan, VirusTotal, Slack
│   └── core/              # Continuous monitoring, live dashboard
├── web/
│   ├── app.py             # Flask web server
│   ├── templates/         # HTML templates
│   └── static/            # CSS, JavaScript
├── data/                   # MITRE ATT&CK data, CVE cache, scan history
├── reports/               # Generated reports (gitignored)
└── main.py               # CLI entry point

## Technical Details

**What Makes It Fast**
- Multi-threaded port scanning (100 concurrent threads)
- CVE result caching (won't hit NVD repeatedly)
- Smart rate limiting for external APIs

**Security Considerations**
- Skips private IPs for Shodan/VT checks automatically
- Never actually tests credentials (flags risk only)
- Rate-limited to respect API quotas
- Stores API keys in environment/args, never in code

**What It Doesn't Do**
- Exploit vulnerabilities (this is a mapper, not a pentesting framework)
- Perform active attacks or fuzzing
- Modify target systems
- Store credentials or sensitive data

## Compliance Frameworks Supported

**PCI-DSS v4.0** - Payment Card Industry
- Requirement 2.1: Change vendor defaults
- Requirement 2.2: Disable unnecessary services
- Requirement 4.1: Use strong cryptography
- Requirement 4.2: Never send PANs by unencrypted means

**NIST Cybersecurity Framework**
- PR.DS-2: Data in transit protection
- DE.CM-8: Vulnerability scanning
- PR.AC-4: Access control management

**CIS Controls v8**
- Control 1.1: Asset inventory
- Control 4.1: Secure configuration
- Control 7.1: Vulnerability management

## Features Breakdown

**8 Major Features:**

1. **Multi-Format Reporting** - JSON, HTML, PDF, CSV exports
2. **Continuous Monitoring** - Change detection with alerting
3. **Slack Integration** - Real-time notifications
4. **Export Hub** - Multiple export formats and webhooks
5. **Threat Intelligence** - Shodan and VirusTotal integration
6. **Compliance Analysis** - PCI-DSS, NIST CSF, CIS Controls
7. **Live Terminal Dashboard** - ASCII art with real-time updates
8. **Web Dashboard** - Modern web UI with charts and graphs

## Known Limitations

- Requires nmap installed on the system
- Free API tiers limit how many IPs you can check
- Can't scan through firewalls (obviously)
- Python 3.8+ required
- macOS and Linux only (Windows might work but untested)
- Web UI runs on development server (use gunicorn for production)

## Screenshots

*TODO: Add screenshots of:*
- Terminal dashboard in action
- Web interface with live scanning
- Generated HTML report
- PDF report sample
- Compliance analysis output

## Contributing

Found a bug? Have an idea? Open an issue or PR.

This is a portfolio project but I'm always interested in making it better.

## Legal

**For authorized security testing only.** 

Don't scan networks you don't own or have explicit permission to test. Unauthorized port scanning is illegal in many jurisdictions. You've been warned.

## License

MIT - do whatever you want with it.

## Author

Built by Ahmed Dahdouh as a portfolio project demonstrating:
- Python development and system architecture
- Security assessment methodology
- MITRE ATT&CK framework knowledge
- Compliance framework understanding
- Integration with external APIs and services
- Professional reporting and data visualization
- Web development (Flask, WebSockets, real-time updates)
- Modern UI/UX design

**This project showcases:**
- 2000+ lines of production Python code
- 25+ files with professional architecture
- 13+ external integrations
- 4 report formats
- 3 user interfaces (CLI, terminal, web)
- Real-time communication with WebSockets
- Multi-threaded performance optimization
- Enterprise-grade security tooling

If you're hiring security engineers, Python developers, or full-stack engineers who understand both security and development - let's talk.

**GitHub:** https://github.com/AhmedDAH1/attack-surface-mapper

---

**Clone it. Run it. Break it. Fix it. Ship it.**
