# Security Policy

## Ethical Use

This tool performs active network reconnaissance (host discovery, port scanning, service enumeration, configuration auditing, and third-party intelligence lookups via Shodan and VirusTotal). It is intended for:

- Scanning networks you own
- Authorized security assessments and penetration-testing engagements
- Defensive security teams auditing their own infrastructure
- Capture-the-flag exercises in isolated lab environments

**Unauthorized scanning of networks you do not own or have explicit written permission to test is illegal in most jurisdictions** (Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, Article 303a StGB in Germany, etc.). The author assumes no responsibility for misuse.

If you cannot answer "yes" to *"Do I have explicit authorization to scan this target?"*, do not run this tool against it.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please **do not** open a public GitHub issue. Instead, report it privately:

- Via [GitHub Security Advisories](https://github.com/AhmedDAH1/attack-surface-mapper/security/advisories), or
- Via [LinkedIn](https://www.linkedin.com/in/ahmed-dahdouh)

I will acknowledge receipt within 72 hours and coordinate a fix before any public disclosure.

## Scope

This is a learning project for a portfolio. It is **not intended for production penetration-testing engagements** without further hardening. Specifically:

- The web dashboard uses Flask's development server (not a production WSGI server like gunicorn)
- The CLI requires `nmap` installed on the host system
- No authentication on the web UI — do not expose the running instance to untrusted networks
- API keys for Shodan, VirusTotal, and Slack are passed via CLI args or environment; they are not stored encrypted

## Credentials and Third-Party APIs

This project integrates with Shodan, VirusTotal, and Slack via API keys. Keys must be provided via CLI flags (`--shodan-key`, `--vt-key`, `--slack-webhook`) or environment variables. **Never commit API keys to the repository.** If you find a committed credential anywhere in the project history, please report it privately so it can be revoked.

External services queried by this tool (Shodan, VirusTotal, NVD) have their own terms of service. Free-tier rate limits apply (100 Shodan queries/month, 500 VirusTotal requests/day, ~50 NVD requests/30s without API key).

## Out of Scope

- The bundled sample MITRE ATT&CK data file (`data/mitre_enterprise.json`) — this is a public dataset
- Known limitation that the web UI runs on Flask's dev server, documented in the README
