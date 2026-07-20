# ThreatByt Reconnaissance Engine (v1.0.0)

`ThreatByt` is a lightweight, high-performance, interactive Command Line Interface (CLI) reconnaissance tool designed for bug bounty hunters, penetration testers, and security researchers. It runs out of the box on **Kali Linux** or any platform with **Python 3.x** and requires **zero external pip dependencies**.

---

## Key Features

### 🔍 1. Passive Reconnaissance
Gathers intelligence without sending any traffic to the target:
- **Base Profiling**: Retrieves target IP, ISP, Organization, Autonomous System Number (ASN), and country mapping using the public RDAP infrastructure.
- **DNS Lookup**: Queries `A`, `NS`, `MX`, and `TXT` records (with automated SPF/DMARC analysis) via public DNS endpoints.
- **Subdomain Harvester**: Collects subdomains passively by scraping SSL/TLS Certificate Transparency logs (`crt.sh`) and the `HackerTarget` search indexes.
- **Technology Stack Profiler**: Fingerprints web servers, server-side frameworks (PHP, ASP.NET, Express), CMS templates (WordPress, Joomla, Drupal), frontend frameworks (React, Vue, jQuery), and cookies signatures.
- **Missing Security Headers**: Identifies missing security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
- **Exploit & CVE Mapper**: Maps identified software versions against the Exploit Database (via local `searchsploit` command execution) and falls back to online CVE directories.

### ⚡ 2. Active Reconnaissance
Directly probes the target securely and concurrently:
- **Subdomain Prober**: Checks which of the passively harvested subdomains are active using multi-threaded HTTP/HTTPS HEAD queries, parsing status codes, and fetching web page titles.
- **Fast TCP Port Scanner**: Scans the target IP for the top 25 high-value ports (SSH, RDP, FTP, Databases, Web, etc.) using a custom multi-threaded Python socket engine with banner grabbing support.
- **Directory / File Fuzzer**: Crawls the web target concurrently to locate critical exposed files or endpoints (like `.env`, `.git/HEAD`, `wp-config.php`, backups, admin panels).

---

## Installation & Requirements

ThreatByt runs on any system with **Python 3.x**.

No installation or external packages (`pip`) are required.

```bash
# Clone the repository (or navigate to the workspace)
cd threatbyt

# Make it executable
chmod +x threatbyt.py
```

*Note: For local exploit correlation, the tool will automatically check if `searchsploit` is present in your shell path (standard on Kali Linux) and use it. Otherwise, it queries public CVE search APIs.*

---

## Usage

### Interactive Mode (Recommended)
Simply execute the main script without arguments to open the custom ThreatByt CLI:
```bash
python threatbyt.py
```

### Command Line Mode
Run specific recon scans directly via arguments:
```bash
# Run Passive Recon only on a target
python threatbyt.py -d example.com -m passive

# Run Active Recon only
python threatbyt.py -d example.com -m active

# Run Full Scan (Passive + Active)
python threatbyt.py -d example.com -m full
```

---

## Scan Reports
Every scan automatically generates a detailed text report in the current directory:
`threatbyt_<domain>_<timestamp>.txt`

These files are fully structured, grouping findings by category, clean from terminal escape colors, and ready for reporting or pipeline parsing.
