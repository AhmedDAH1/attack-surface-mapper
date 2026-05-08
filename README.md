# Attack Surface Mapper

A Python-based security assessment tool that discovers network vulnerabilities, maps them to MITRE ATT&CK techniques, and checks compliance against major frameworks.

Built to automate the tedious parts of security assessments while providing actionable insights that matter.

## Why I Built This

After running countless manual security scans, I got tired of:
- Spending hours on repetitive port scanning and service enumeration
- Manually mapping findings to MITRE ATT&CK
- Writing the same compliance reports over and over
- Not knowing when my attack surface changed

So I automated it. This tool does what I used to do manually - discover services, find misconfigurations, check compliance, and alert me when things change.

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

# Scan with all the bells and whistles
python main.py scan 192.168.1.100 \
  --shodan-key YOUR_KEY \
  --vt-key YOUR_KEY \
  --slack-webhook https://hooks.slack.com/... \
  -o full_assessment
```

That's it. No complex setup, no configuration files to edit.

## Real-World Usage

**Security Assessment**
```bash
# Scan a target network
python main.py scan 192.168.1.0/24 -o client_assessment

# You get 4 reports automatically:
# - client_assessment.json (for automation)
# - client_assessment.html (interactive dashboard)
# - client_assessment.pdf (professional report)
# - client_assessment.csv (for spreadsheets)
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

## What the Output Looks Like

**Terminal Output**
[PHASE 1] Network Discovery
Found 5 open ports on 3 hosts
[PHASE 2] Service Enumeration
SSH OpenSSH 7.4
HTTP Apache 2.4.41
MySQL 5.7.33
[PHASE 3] MITRE ATT&CK Mapping
Identified 8 attack techniques across 4 tactics
[PHASE 3.7] Compliance Analysis
Score: 65/100 - WEAK
PCI-DSS: 3 violations
NIST CSF: 2 violations
[!] CRITICAL: Default credentials on 192.168.1.100:22

**HTML Dashboard** (interactive, actually useful)
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
# Basic scan
python main.py scan <target>

# Scan specific ports
python main.py scan <target> -p 22,80,443,3306

# Skip slow parts for quick scans
python main.py scan <target> --skip-cve

# Custom output name
python main.py scan <target> -o my_scan_name

# Continuous monitoring
python main.py monitor <target> --interval 60

# Limited monitoring (run 5 scans then stop)
python main.py monitor <target> -i 30 -n 5

# Full enterprise scan
python main.py scan <target> \
  --shodan-key KEY \
  --vt-key KEY \
  --slack-webhook URL \
  -o enterprise_assessment
```

## Project Structure
attack-surface-mapper/
├── src/
│   ├── scanners/           # Port scanning, enumeration, config auditing
│   ├── analyzers/          # MITRE mapping, compliance checking
│   ├── reporters/          # JSON, HTML, PDF, CSV generation
│   ├── integrations/       # Shodan, VirusTotal, Slack
│   └── core/              # Continuous monitoring engine
├── data/                   # MITRE ATT&CK data, CVE cache, scan history
├── reports/               # Generated reports (gitignored)
└── main.py               # Entry point
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

## Known Limitations

- Requires nmap installed on the system
- Free API tiers limit how many IPs you can check
- Can't scan through firewalls (obviously)
- Python 3.8+ required
- macOS and Linux only (Windows might work but untested)

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

If you're hiring security engineers or Python developers, let's talk.

---

**That's it. Clone it, run it, break it, fix it.**
