#!/usr/bin/env python3
"""
ThreatByt Recon Tool - Main Entry Script
Automates passive and active reconnaissance for bug bounty hunters and pen testers.
Includes a state-of-the-art interactive HTML dashboard exporter.
"""

import os
import sys
import argparse
from datetime import datetime
import urllib.parse

# Import modules
import passive_engine
import active_engine

# ANSI Escape Colors for Premium Terminal Feel
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[1;34m'
MAGENTA = '\033[1;35m'
CYAN = '\033[1;36m'
RESET = '\033[0m'
BOLD = '\033[1m'

BANNER = f"""{RED}
  _____ _                    _   ____        _   
 |_   _| |__  _ __ ___  __ _| |_| __ ) _   _| |_ 
   | | | '_ \\| '__/ _ \\/ _` | __|  _ \\| | | | __|
   | | | | | | | |  __/ (_| | |_| |_) | |_| | |_ 
   |_| |_| |_|_|  \\___|\\__,_|\\__|____/ \\__, |\\__|
                                       |___/     
{CYAN}            [ ThreatByt Reconnaissance Engine v1.0 ]
            [ Developed for Bug Bounty & Pentesting ]
{RESET}"""

def clean_domain(input_target):
    input_target = input_target.strip().lower()
    if not input_target.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse('http://' + input_target)
    else:
        parsed = urllib.parse.urlparse(input_target)
    
    domain = parsed.netloc.split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def generate_html_report(domain, passive_data, active_data, text_report_path):
    """
    Generates a premium glassmorphic dark-mode HTML report dashboard
    with responsive grids, badges, and real-time JavaScript table filters.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"threatbyt_{domain}_{file_timestamp}.html"
    
    # Extract fields safely
    ip = passive_data.get('ip', 'N/A')
    base_info = passive_data.get('base_info', {})
    dns_info = passive_data.get('dns_info', {})
    shodan_ports = passive_data.get('shodan_ports', [])
    otx = passive_data.get('otx_threats', {})
    tech_stack = passive_data.get('tech_stack', [])
    headers = passive_data.get('headers', {})
    missing_headers = passive_data.get('missing_headers', [])
    vulns = passive_data.get('vulns', [])
    passive_subs = passive_data.get('subdomains', [])
    
    active_subs = active_data.get('live_subdomains', [])
    active_ports = active_data.get('open_ports', [])
    fuzz_results = active_data.get('fuzz_results', [])
    
    # Calculate score metrics for Threat Level
    severity_score = 0
    severity_label = "INFORMATIONAL"
    severity_color = "#38bdf8" # Blue
    
    if len(vulns) > 0 or any('critical' in v.lower() for v in vulns):
        severity_score += 45
    if len(fuzz_results) > 0:
        severity_score += len(fuzz_results) * 15
    if len(active_ports) > 0:
        severity_score += len(active_ports) * 10
    if otx and otx.get('pulse_count', 0) > 0:
        severity_score += otx.get('pulse_count', 0) * 15

    if severity_score >= 80:
        severity_label = "HIGH RISK"
        severity_color = "#f43f5e" # Rose/Red
    elif severity_score >= 30:
        severity_label = "MEDIUM RISK"
        severity_color = "#f59e0b" # Amber/Yellow
    elif severity_score > 0:
        severity_label = "LOW RISK"
        severity_color = "#10b981" # Emerald/Green

    # HTML Templates construction
    tech_badges_html = ""
    if tech_stack:
        for tech in tech_stack:
            tech_badges_html += f'<span class="badge badge-tech">{tech}</span>\n'
    else:
        tech_badges_html = '<span class="text-muted">No technologies fingerprinted.</span>'

    missing_headers_html = ""
    if missing_headers:
        for header in missing_headers:
            missing_headers_html += f'<div class="header-item red">✖ Missing {header}</div>\n'
    else:
        missing_headers_html = '<div class="header-item green">✔ All standard security headers observed.</div>'

    dns_tables_html = ""
    for rtype, records in dns_info.items():
        if records:
            dns_tables_html += f"""
            <div class="dns-block">
                <h4>{rtype} Records</h4>
                <ul>
                    {"".join(f"<li>{r}</li>" for r in records)}
                </ul>
            </div>
            """

    vuln_list_html = ""
    if vulns:
        for vuln in vulns:
            vuln_list_html += f'<div class="vuln-item">{vuln}</div>\n'
    else:
        vuln_list_html = '<div class="text-muted">No vulnerabilities correlated with identified software.</div>'

    shodan_ports_html = ""
    if shodan_ports:
        shodan_ports_html = " ".join(f'<span class="badge badge-port">{p}</span>' for p in sorted(shodan_ports))
    else:
        shodan_ports_html = '<span class="text-muted">None listed.</span>'

    otx_html = ""
    if otx and otx.get('pulse_count', 0) > 0:
        otx_html = f"""
        <div class="otx-box">
            <strong>{otx['pulse_count']} pulse(s) detected in AlienVault OTX</strong>
            <ul>
                {"".join(f"<li>Indicator Ref: {p}</li>" for p in otx['pulses'])}
            </ul>
        </div>
        """
    else:
        otx_html = '<p class="text-muted">Domain holds clear IP reputation logs.</p>'

    subdomains_rows = ""
    all_subs_set = set(passive_subs)
    all_subs_set.update(s['subdomain'] for s in active_subs)
    
    # Compile a dictionary for status lookup
    active_lookup = {s['subdomain']: s for s in active_subs}
    
    for idx, sub in enumerate(sorted(list(all_subs_set)), 1):
        if sub in active_lookup:
            status_badge = f'<span class="status-live">LIVE ({active_lookup[sub]["status"]})</span>'
            title = active_lookup[sub]['title']
            url = f'<a href="{active_lookup[sub]["url"]}" target="_blank" class="text-link">{active_lookup[sub]["url"]}</a>'
        else:
            status_badge = '<span class="status-passive">PASSIVE ONLY</span>'
            title = 'N/A'
            url = f'http://{sub}'
            url = f'<a href="{url}" target="_blank" class="text-link-passive">{sub}</a>'
            
        subdomains_rows += f"""
        <tr>
            <td>{idx}</td>
            <td class="font-mono">{sub}</td>
            <td>{status_badge}</td>
            <td class="font-mono text-muted">{title}</td>
            <td>{url}</td>
        </tr>
        """

    ports_rows = ""
    if active_ports:
        for port in sorted(active_ports, key=lambda x: x['port']):
            banner = port['banner'] if port['banner'] else 'No banner returned'
            ports_rows += f"""
            <tr>
                <td class="font-bold">{port['port']}/TCP</td>
                <td><span class="status-live">OPEN</span></td>
                <td class="font-bold">{port['service']}</td>
                <td class="font-mono text-muted">{banner}</td>
            </tr>
            """
    else:
        ports_rows = '<tr><td colspan="4" class="text-center text-muted">No open TCP interfaces identified.</td></tr>'

    fuzz_rows = ""
    if fuzz_results:
        for res in fuzz_results:
            is_critical = any(crit in res['path'] for crit in ['.env', '.git', 'config', 'htaccess'])
            badge_class = 'badge-danger' if is_critical else 'badge-warn'
            label = 'EXPOSED FILE' if is_critical else 'RESTRICTED PATH'
            fuzz_rows += f"""
            <tr>
                <td class="font-mono"><span class="badge {badge_class}">{label}</span></td>
                <td class="font-mono"><a href="{res['url']}" target="_blank" class="text-link">{res['url']}</a></td>
                <td class="font-bold">{res['status']}</td>
            </tr>
            """
    else:
        fuzz_rows = '<tr><td colspan="3" class="text-center text-muted">Fuzzer completed with zero credentials or exposed structures.</td></tr>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatByt Recon Engine - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0b0f19;
            --card-bg: rgba(20, 29, 47, 0.7);
            --border-glow: rgba(147, 51, 234, 0.25);
            --neon-purple: #a855f7;
            --neon-cyan: #06b6d4;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            line-height: 1.6;
            padding: 30px 10%;
        }}
        
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-glow);
            padding-bottom: 25px;
            margin-bottom: 35px;
        }}
        
        .brand {{
            font-size: 32px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 1px;
        }}
        
        .brand span {{
            color: var(--neon-purple);
        }}
        
        .meta-stamp {{
            text-align: right;
            font-size: 13px;
            color: var(--text-muted);
        }}
        
        .grid-overview {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .card-stat {{
            background: var(--card-bg);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 22px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }}
        
        .card-stat:hover {{
            transform: translateY(-4px);
            border-color: var(--neon-cyan);
        }}
        
        .card-stat h3 {{
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }}
        
        .card-stat .value {{
            font-size: 26px;
            font-weight: 700;
            font-family: 'Space Mono', monospace;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            color: #0b0f19;
        }}
        
        .section-title {{
            font-size: 22px;
            font-weight: 600;
            border-left: 4px solid var(--neon-purple);
            padding-left: 12px;
            margin-bottom: 20px;
            color: #ffffff;
        }}
        
        .dashboard-layout {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 45px;
        }}
        
        @media (max-width: 1024px) {{
            .dashboard-layout {{
                grid-template-columns: 1fr;
            }}
            body {{
                padding: 20px 5%;
            }}
        }}
        
        .panel {{
            background: var(--card-bg);
            border: 1px solid var(--border-glow);
            border-radius: 14px;
            padding: 25px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin: 4px;
            font-family: 'Outfit', sans-serif;
        }}
        
        .badge-tech {{
            background: rgba(168, 85, 247, 0.15);
            border: 1px solid var(--neon-purple);
            color: #e9d5ff;
        }}
        
        .badge-port {{
            background: rgba(6, 182, 212, 0.15);
            border: 1px solid var(--neon-cyan);
            color: #cffafe;
        }}
        
        .badge-danger {{
            background: rgba(244, 63, 94, 0.15);
            border: 1px solid #f43f5e;
            color: #ffe4e6;
        }}
        
        .badge-warn {{
            background: rgba(245, 158, 11, 0.15);
            border: 1px solid #f59e0b;
            color: #fef3c7;
        }}
        
        .header-item {{
            margin-bottom: 8px;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
        }}
        
        .header-item.red {{
            background: rgba(244, 63, 94, 0.08);
            border: 1px solid rgba(244, 63, 94, 0.3);
            color: #fda4af;
        }}
        
        .header-item.green {{
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #6ee7b7;
        }}
        
        .dns-block {{
            background: rgba(15, 23, 42, 0.5);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 12px;
            border-left: 3px solid var(--neon-cyan);
        }}
        
        .dns-block h4 {{
            font-size: 14px;
            color: var(--neon-cyan);
            margin-bottom: 8px;
            text-transform: uppercase;
        }}
        
        .dns-block ul {{
            list-style: none;
            padding-left: 5px;
        }}
        
        .dns-block li {{
            font-family: 'Space Mono', monospace;
            font-size: 13px;
            color: #d1d5db;
            word-break: break-all;
        }}
        
        .vuln-item {{
            padding: 12px;
            background: rgba(244, 63, 94, 0.05);
            border: 1px solid rgba(244, 63, 94, 0.2);
            border-radius: 8px;
            margin-bottom: 10px;
            font-size: 13px;
            color: #fca5a5;
            font-family: 'Space Mono', monospace;
        }}
        
        .otx-box {{
            background: rgba(245, 158, 11, 0.05);
            border: 1px solid rgba(245, 158, 11, 0.2);
            border-radius: 8px;
            padding: 15px;
            font-size: 13px;
        }}
        
        .otx-box ul {{
            padding-left: 20px;
            margin-top: 8px;
        }}
        
        .full-width-panel {{
            background: var(--card-bg);
            border: 1px solid var(--border-glow);
            border-radius: 14px;
            padding: 30px;
            margin-bottom: 45px;
        }}
        
        .search-box {{
            width: 100%;
            max-width: 320px;
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid var(--border-glow);
            padding: 10px 16px;
            border-radius: 8px;
            color: #ffffff;
            font-family: 'Outfit', sans-serif;
            font-size: 14px;
            margin-bottom: 20px;
            outline: none;
            transition: border-color 0.2s ease;
        }}
        
        .search-box:focus {{
            border-color: var(--neon-cyan);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            text-align: left;
        }}
        
        th, td {{
            padding: 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }}
        
        th {{
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }}
        
        .status-live {{
            display: inline-block;
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            color: #a7f3d0;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        
        .status-passive {{
            display: inline-block;
            background: rgba(156, 163, 175, 0.15);
            border: 1px solid #9ca3af;
            color: #e5e7eb;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        
        .text-link {{
            color: var(--neon-cyan);
            text-decoration: none;
            transition: color 0.1s ease;
        }}
        
        .text-link:hover {{
            color: #a5f3fc;
            text-decoration: underline;
        }}
        
        .text-link-passive {{
            color: var(--text-muted);
            text-decoration: none;
        }}
        
        .font-mono {{
            font-family: 'Space Mono', monospace;
            font-size: 13px;
        }}
        
        .font-bold {{
            font-weight: 600;
        }}
        
        .text-center {{
            text-align: center;
        }}
        
        .text-muted {{
            color: var(--text-muted);
        }}
        
        footer {{
            text-align: center;
            padding: 20px 0;
            font-size: 13px;
            color: var(--text-muted);
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            margin-top: 30px;
        }}
    </style>
</head>
<body>

    <header>
        <div class="brand">Threat<span>Byt</span></div>
        <div class="meta-stamp">
            <p>Target: <strong>{domain}</strong></p>
            <p>Generated: {timestamp}</p>
        </div>
    </header>

    <div class="grid-overview">
        <div class="card-stat">
            <h3>Target IP</h3>
            <div class="value" style="color: var(--neon-cyan);">{ip}</div>
        </div>
        <div class="card-stat">
            <h3>Subdomains</h3>
            <div class="value">{len(all_subs_set)}</div>
        </div>
        <div class="card-stat">
            <h3>Open Ports</h3>
            <div class="value">{len(active_ports)}</div>
        </div>
        <div class="card-stat">
            <h3>Risk Severity</h3>
            <div class="value">
                <span class="severity-badge" style="background-color: {severity_color};">{severity_label}</span>
            </div>
        </div>
    </div>

    <div class="dashboard-layout">
        <div class="panel">
            <h2 class="section-title">Passive IP & DNS Profile</h2>
            
            <div style="margin-bottom: 20px;">
                <strong>ISP / Organization:</strong>
                <p class="text-muted" style="margin-top: 4px;">{base_info.get('isp', 'N/A')} ({base_info.get('org', 'N/A')})</p>
            </div>
            
            <div style="margin-bottom: 20px;">
                <strong>Country:</strong>
                <p class="text-muted" style="margin-top: 4px;">{base_info.get('country', 'N/A')}</p>
            </div>
            
            <div style="margin-bottom: 25px;">
                <strong>Shodan Open Ports:</strong>
                <div style="margin-top: 8px;">{shodan_ports_html}</div>
            </div>

            <strong>DNS Map</strong>
            <div style="margin-top: 10px;">
                {dns_tables_html}
            </div>
        </div>

        <div class="panel">
            <h2 class="section-title">Technology & Vuln Intelligence</h2>
            
            <div style="margin-bottom: 25px;">
                <strong>Identified Technologies</strong>
                <div style="margin-top: 8px;">
                    {tech_badges_html}
                </div>
            </div>
            
            <div style="margin-bottom: 25px;">
                <strong>Security Headers Audit</strong>
                <div style="margin-top: 10px;">
                    {missing_headers_html}
                </div>
            </div>
            
            <div style="margin-bottom: 25px;">
                <strong>Vulnerability Mapping</strong>
                <div style="margin-top: 10px;">
                    {vuln_list_html}
                </div>
            </div>

            <div style="margin-bottom: 10px;">
                <strong>OTX Reputation Intelligence</strong>
                <div style="margin-top: 10px;">
                    {otx_html}
                </div>
            </div>
        </div>
    </div>

    <div class="dashboard-layout">
        <div class="panel">
            <h2 class="section-title">Active TCP Infrastructure</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Banner Grab</th>
                    </tr>
                </thead>
                <tbody>
                    {ports_rows}
                </tbody>
            </table>
        </div>

        <div class="panel">
            <h2 class="section-title">Directory Fuzzer Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Endpoint URL</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {fuzz_rows}
                </tbody>
            </table>
        </div>
    </div>

    <div class="full-width-panel">
        <h2 class="section-title">Target Subdomain Inventory</h2>
        <input type="text" id="subdomainSearch" class="search-box" placeholder="Filter subdomains by search query..." onkeyup="filterSubdomains()">
        <table id="subdomainsTable">
            <thead>
                <tr>
                    <th style="width: 60px;">#</th>
                    <th>Subdomain</th>
                    <th>Scan Status</th>
                    <th>Web Page Title</th>
                    <th>Primary Interface Link</th>
                </tr>
            </thead>
            <tbody>
                {subdomains_rows}
            </tbody>
        </table>
    </div>

    <footer>
        <p>ThreatByt Reconnaissance Engine | Standalone Security Intelligence Dashboard</p>
    </footer>

    <script>
        function filterSubdomains() {{
            var input = document.getElementById("subdomainSearch");
            var filter = input.value.toLowerCase();
            var table = document.getElementById("subdomainsTable");
            var tr = table.getElementsByTagName("tr");
            
            // Loop through all table rows, starting from 1 (header row is 0)
            for (var i = 1; i < tr.length; i++) {{
                var td = tr[i].getElementsByTagName("td")[1]; // Subdomain column
                if (td) {{
                    var txtValue = td.textContent || td.innerText;
                    if (txtValue.toLowerCase().indexOf(filter) > -1) {{
                        tr[i].style.display = "";
                    }} else {{
                        tr[i].style.display = "none";
                    }}
                }}
            }}
        }}
    </script>
</body>
</html>
"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"{GREEN}[+] Premium HTML Dashboard exported: {BOLD}{filename}{RESET}")
        return filename
    except Exception as e:
        print(f"{RED}[!] Error exporting HTML Dashboard: {e}{RESET}")
        return None

def run_recon(domain, mode):
    print(f"\n{BLUE}[*] Target Domain: {BOLD}{domain}{RESET}")
    print(f"{BLUE}[*] Scan Mode: {BOLD}{mode.upper()}{RESET}")
    print(f"{BLUE}[*] Starting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n")

    report_content = []
    report_content.append("="*60)
    report_content.append(f" THREATBYT RECONNAISSANCE REPORT")
    report_content.append(f" Target: {domain}")
    report_content.append(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_content.append(f" Mode: {mode.upper()}")
    report_content.append("="*60 + "\n")

    passive_results = {}
    active_results = {}

    if mode in ['passive', 'full']:
        passive_results = passive_engine.run(domain)
        report_content.append("## PASSIVE RECONNAISSANCE FINDINGS ##\n")
        report_content.append(passive_results.get('report', 'No passive data gathered.'))
        report_content.append("\n" + "="*40 + "\n")

    if mode in ['active', 'full']:
        subdomains = passive_results.get('subdomains', [])
        active_results = active_engine.run(domain, subdomains)
        report_content.append("## ACTIVE RECONNAISSANCE FINDINGS ##\n")
        report_content.append(active_results.get('report', 'No active data gathered.'))
        report_content.append("\n" + "="*40 + "\n")

    # Generate files
    full_report = "\n".join(report_content)
    text_report_path = save_report(domain, full_report)
    
    # Export interactive dashboard
    generate_html_report(
        domain=domain,
        passive_data=passive_results.get('structured_data', {}),
        active_data=active_results.get('structured_data', {}),
        text_report_path=text_report_path
    )
    print(f"\n{GREEN}[+] ThreatByt Scan Completed!{RESET}")

def save_report(domain, report_data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"threatbyt_{domain}_{timestamp}.txt"
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_data)
        print(f"{GREEN}[+] Text report archived: {BOLD}{filename}{RESET}")
        return filename
    except Exception as e:
        print(f"\n{RED}[!] Error saving text report: {e}{RESET}")
        return None

def interactive_menu():
    print(BANNER)
    try:
        target_input = input(f"{BOLD}Enter Target Domain/IP (e.g., example.com): {RESET}").strip()
        if not target_input:
            print(f"{RED}[!] Target domain cannot be empty.{RESET}")
            return
        
        domain = clean_domain(target_input)
        
        print(f"\n{BOLD}Select Reconnaissance Mode:{RESET}")
        print(f"  {GREEN}[1]{RESET} Passive Recon (Cert logs, DNS, Tech, Shodan DB, CVEs)")
        print(f"  {GREEN}[2]{RESET} Active Recon (Subdomain probing, Ports scan, Directory fuzz)")
        print(f"  {GREEN}[3]{RESET} Full Scan (Passive + Active)")
        print(f"  {RED}[4]{RESET} Exit")
        
        choice = input(f"\n{BOLD}ThreatByt > {RESET}").strip()
        
        if choice == '1':
            run_recon(domain, 'passive')
        elif choice == '2':
            run_recon(domain, 'active')
        elif choice == '3':
            run_recon(domain, 'full')
        elif choice == '4' or choice.lower() == 'exit':
            print(f"\n{YELLOW}[*] Happy Hunting! Exiting ThreatByt.{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[!] Invalid choice. Exiting.{RESET}")
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Scan aborted by user. Exiting ThreatByt.{RESET}")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="ThreatByt Recon Engine - Premium Bug Bounty Recon Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python threatbyt.py -d example.com -m passive\n  python threatbyt.py (for interactive menu)"
    )
    parser.add_argument("-d", "--domain", help="Target domain or IP address")
    parser.add_argument("-m", "--mode", choices=["passive", "active", "full"], help="Scan mode")
    
    args = parser.parse_args()
    
    if args.domain:
        domain = clean_domain(args.domain)
        mode = args.mode if args.mode else "passive"
        print(BANNER)
        run_recon(domain, mode)
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
