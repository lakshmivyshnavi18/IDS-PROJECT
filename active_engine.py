import socket
import urllib.request
import urllib.error
import ssl
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI Colors for Output
GREEN = '\033[1;32m'
RED = '\033[1;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[1;34m'
CYAN = '\033[1;36m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Expanded list of 60+ critical security fuzzing endpoints
COMMON_PATHS = [
    # Git & Credentials leaks
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".env",
    ".env.local",
    ".env.production",
    ".env.dev",
    ".git-credentials",
    ".aws/credentials",
    ".vscode/sftp.json",
    
    # CMS / Framework Configs
    "wp-config.php",
    "wp-config.txt",
    "wp-config.php.bak",
    "config.php",
    "config.php.bak",
    "config.json",
    "config/database.yml",
    "database.yml",
    "web.config",
    "nginx.conf",
    ".htaccess",
    "docker-compose.yml",
    
    # Backups & Databases
    "backup.zip",
    "backup.tar.gz",
    "backup.rar",
    "backup.tgz",
    "backup/",
    "backups/",
    "back.zip",
    "database.sql",
    "db.sql",
    "dump.sql",
    "backup.sql",
    "db_backup.sql",
    
    # Meta / Info Files
    "robots.txt",
    "sitemap.xml",
    "phpinfo.php",
    "info.php",
    "server-status",
    "server-info",
    
    # Admin / Auth portals
    "admin/",
    "administrator/",
    "admin.php",
    "admin/login.php",
    "wp-admin/",
    "wp-login.php",
    "login/",
    "login.php",
    "dashboard/",
    "user/login",
    "cpanel/",
    "webmail/",
    "console/",
    
    # API endpoints & Dev tools
    "api/",
    "api/v1/",
    "api/v2/",
    "swagger.json",
    "swagger-ui.html",
    "api-docs",
    "graphql/",
    "composer.json",
    "package.json",
    "composer.lock",
    "package-lock.json",
    
    # Backdoors & Debug panels
    "elmah.axd",
    "actuator/health",
    "actuator/env",
    "actuator/",
    "debug.log",
    "error.log",
    "access.log"
]

# Top 25 high-value ports for bug hunting
TOP_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    873: "Rsync",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9000: "SonarQube/Web",
    27017: "MongoDB"
}

def print_progress(current, total, prefix="Progress"):
    """
    Renders a premium progress loader bar in the console using CP1252/Windows safe ASCII characters.
    """
    percent = int(100 * (current / total))
    filled_length = int(25 * current // total)
    bar = '=' * filled_length + '-' * (25 - filled_length)
    sys.stdout.write(f"\r{BLUE}[*]{RESET} {prefix}: |{bar}| {percent}% ({current}/{total})")
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\r" + " " * 80 + "\r") # Clear the progress line when done
        sys.stdout.flush()


def probe_subdomain(subdomain):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for proto in ['https://', 'http://']:
        url = f"{proto}{subdomain}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
                status = response.status
                html = response.read(1500).decode('utf-8', errors='ignore')
                title_match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
                title = title_match.group(1).strip() if title_match else 'No Title'
                title = " ".join(title.split())
                return {'subdomain': subdomain, 'live': True, 'url': url, 'status': status, 'title': title[:45]}
        except urllib.error.HTTPError as e:
            return {'subdomain': subdomain, 'live': True, 'url': url, 'status': e.code, 'title': f'HTTP Error {e.code}'}
        except Exception:
            continue
            
    return {'subdomain': subdomain, 'live': False}

def scan_port(ip, port, service_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.2)
    try:
        s.connect((ip, port))
        banner = ""
        try:
            if port in [21, 22, 25]:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        return {'port': port, 'status': 'open', 'service': service_name, 'banner': banner[:50]}
    except Exception:
        return {'port': port, 'status': 'closed'}
    finally:
        s.close()

def fuzz_path(domain, path):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for proto in ['https://', 'http://']:
        url = f"{proto}{domain}/{path}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
                return {'path': path, 'url': url, 'status': response.status, 'found': True}
        except urllib.error.HTTPError as e:
            if e.code in [403, 401]:
                return {'path': path, 'url': url, 'status': e.code, 'found': True}
            return {'path': path, 'found': False}
        except Exception:
            continue
    return {'path': path, 'found': False}

def run(domain, passive_subdomains=None):
    print(f"\n{BOLD}{CYAN}=== Launching ThreatByt Active Recon Engine ==={RESET}")
    
    report = []
    structured_active = {
        'live_subdomains': [],
        'open_ports': [],
        'fuzz_results': []
    }
    
    # 1. Live Subdomain Probing
    live_subdomains = []
    if passive_subdomains:
        total_subs = len(passive_subdomains)
        print(f"{BLUE}[*]{RESET} Probing {total_subs} subdomains using thread pool...")
        completed = 0
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(probe_subdomain, sub): sub for sub in passive_subdomains}
            for fut in as_completed(futures):
                res = fut.result()
                completed += 1
                print_progress(completed, total_subs, prefix="Subdomain Probe")
                if res.get('live'):
                    live_subdomains.append(res)
                    structured_active['live_subdomains'].append(res)
                    
        print(f"\n{GREEN}[+] Active Hosts Discovered ({len(live_subdomains)}):{RESET}")
        report.append(f"--- LIVE SUBDOMAINS ({len(live_subdomains)}) ---")
        for live in live_subdomains:
            status_color = GREEN if live['status'] == 200 else YELLOW
            print(f"  [+] {live['url']} [Status: {status_color}{live['status']}{RESET}] [Title: {live['title']}]")
            report.append(f"  - {live['url']} [Status: {live['status']}] [Title: {live['title']}]")
        report.append("")
    else:
        print(f"{YELLOW}[!]{RESET} No subdomain inventory to probe. Skipping domain active checks.")
        report.append("--- SUBDOMAIN PROBING ---\n  No subdomains probed.\n")

    # 2. Port Scanning
    print(f"\n{BLUE}[*]{RESET} Resolving IP target interface for socket scanning...")
    try:
        target_ip = socket.gethostbyname(domain)
        print(f"{BLUE}[*]{RESET} Mapping top 25 high-exposure ports on IP {target_ip}...")
        open_ports = []
        total_ports = len(TOP_PORTS)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(scan_port, target_ip, port, svc): port for port, svc in TOP_PORTS.items()}
            for fut in as_completed(futures):
                res = fut.result()
                completed += 1
                print_progress(completed, total_ports, prefix="TCP Port Scan")
                if res.get('status') == 'open':
                    open_ports.append(res)
                    structured_active['open_ports'].append(res)
                    
        print(f"\n{GREEN}[+] Active TCP Infrastructure:{RESET}")
        report.append("--- OPEN TCP PORTS ---")
        if open_ports:
            for op in sorted(open_ports, key=lambda x: x['port']):
                banner_str = f" | Banner: {op['banner']}" if op['banner'] else ""
                print(f"  [+] Port {BOLD}{op['port']}{RESET}/TCP open ({op['service']}){banner_str}")
                report.append(f"  - Port {op['port']}/TCP open ({op['service']}){banner_str}")
        else:
            print("  [*] Port scan complete: No open ports found in top 25 list.")
            report.append("  - No open ports found in the top 25 list.")
        report.append("")
    except Exception:
        print(f"{RED}[!] Resolution failed: Port scan aborted.{RESET}")
        report.append("--- PORT SCANNING ---\n  Resolution failed.\n")

    # 3. Directory Fuzzing
    print(f"\n{BLUE}[*]{RESET} Brute-forcing 60+ credentials & hidden configuration endpoints...")
    found_paths = []
    total_paths = len(COMMON_PATHS)
    completed = 0
    
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(fuzz_path, domain, path): path for path in COMMON_PATHS}
        for fut in as_completed(futures):
            res = fut.result()
            completed += 1
            print_progress(completed, total_paths, prefix="Directory Fuzz")
            if res.get('found'):
                found_paths.append(res)
                structured_active['fuzz_results'].append(res)
                
    print(f"\n{GREEN}[+] Exposed Files & directories:{RESET}")
    report.append("--- EXPOSED ENDPOINTS ---")
    if found_paths:
        for fp in found_paths:
            is_critical = any(crit in fp['path'] for crit in ['.env', '.git', 'config', 'htaccess', 'backup', 'db.sql', 'composer.json'])
            risk_tag = f"{RED}[CRITICAL]{RESET} " if is_critical else ""
            status_color = GREEN if fp['status'] == 200 else YELLOW
            print(f"  [+] {risk_tag}{fp['url']} [Status: {status_color}{fp['status']}{RESET}]")
            report.append(f"  - {'[CRITICAL] ' if is_critical else ''}{fp['url']} [Status: {fp['status']}]")
    else:
        print("  [*] Directory fuzzing complete: No credentials or leaks identified.")
        report.append("  - No sensitive endpoints found during fuzzing.")
    report.append("")

    return {
        'report': "\n".join(report),
        'structured_data': structured_active
    }
