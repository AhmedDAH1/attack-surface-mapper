# Attack Surface Mapper
 
A Python security tool that scans network infrastructure for vulnerabilities and maps findings to the MITRE ATT&CK framework.
 
## Overview
 
Attack Surface Mapper automates security reconnaissance by:
- Scanning networks for open ports and running services
- Detecting misconfigurations and known vulnerabilities
- Mapping findings to MITRE ATT&CK tactics and techniques
- Generating actionable security reports
## Features
 
**Scanning Modules**
- Network scanner: Port discovery and service detection
- Service enumerator: Version detection and banner analysis
- OS fingerprinting: Operating system and patch level identification
- Configuration auditor: Security misconfiguration detection
**Analysis Engine**
- MITRE ATT&CK framework mapping
- CVE vulnerability correlation
- Risk scoring and prioritization
**Reporting**
- JSON export for automation
- HTML reports for documentation
- Executive summaries with remediation guidance
## Installation
 
```bash
git clone https://github.com/AhmedDAH1/attack-surface-mapper.git
cd attack-surface-mapper
pip install -r requirements.txt
```
 
## Usage
 
```bash
# Scan a single target
python main.py scan --target 192.168.1.100
 
# Scan a network range
python main.py scan --target 192.168.1.0/24 --output report.html
 
# Full analysis with MITRE mapping
python main.py analyze --target 192.168.1.100 --mitre
```
 
## Project Structure
 
```
src/scanners/    - Network and service discovery modules
src/analyzers/   - MITRE mapping and vulnerability analysis
src/reporters/   - Report generation engines
tests/           - Unit and integration tests
data/            - MITRE ATT&CK database and CVE feeds
```
 
## Legal Notice
 
For authorized security testing only. Obtain proper authorization before scanning any network.
 
## License
 
MIT License