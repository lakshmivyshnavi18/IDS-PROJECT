import urllib.request
import urllib.error
import json
import re
import socket
import subprocess
import shutil
import ssl

# ANSI Colors for Output
GREEN = '\033[1;32m'
RED = '\033[1;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[1;34m'
CYAN = '\033[1;36m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Comprehensive Technology Signatures Matrix (50+ Rules)
TECH_SIGNATURES = {
    "Web Servers": [
        ("server", r"nginx", "Nginx"),
        ("server", r"apache", "Apache HTTP Server"),
        ("server", r"microsoft-iis", "Microsoft IIS"),
        ("server", r"litespeed", "LiteSpeed Web Server"),
        ("server", r"caddy", "Caddy Server"),
        ("server", r"gunicorn", "Gunicorn (Python)"),
        ("server", r"tomcat", "Apache Tomcat"),
        ("server", r"cloudflare", "Cloudflare Server Proxy"),
        ("server", r"cloudfront", "Amazon CloudFront Proxy")
    ],
    "CMS": [
        ("html", r"/wp-content/|/wp-includes/|wp-submit\.php", "WordPress"),
        ("html", r"name=\"generator\" content=\"WordPress", "WordPress CMS"),
        ("html", r"name=\"generator\" content=\"Joomla", "Joomla CMS"),
        ("html", r"name=\"generator\" content=\"Drupal", "Drupal CMS"),
        ("html", r"name=\"generator\" content=\"Magento|/skin/frontend/", "Magento E-Commerce"),
        ("html", r"cdn\.shopify\.com|shopify-assets", "Shopify E-Commerce"),
        ("html", r"ghost\.org|/ghost/api/", "Ghost CMS"),
        ("html", r"squarespace\.com|squarespace-headers", "Squarespace Site Builder"),
        ("html", r"wix\.com|wix-code", "Wix Site Builder"),
        ("html", r"bitrix", "Bitrix CMS"),
        ("html", r"blogspot\.com|blogger\.com", "Blogger CMS")
    ],
    "Frameworks & Backend": [
        ("x-powered-by", r"php", "PHP Backend"),
        ("x-powered-by", r"express", "Express (Node.js)"),
        ("x-powered-by", r"asp\.net", "ASP.NET Backend"),
        ("x-powered-by", r"next\.js", "Next.js Framework"),
        ("x-powered-by", r"spring", "Spring Boot (Java)"),
        ("set-cookie", r"PHPSESSID", "PHP Session Handler"),
        ("set-cookie", r"laravel_session", "Laravel Framework"),
        ("set-cookie", r"JSESSIONID", "Java/JSP Session Handler"),
        ("set-cookie", r"sessionid", "Django/Python Session Handler"),
        ("set-cookie", r"csrftoken", "Django / Python CSRF Protection"),
        ("set-cookie", r"cf_clearance", "Cloudflare WAF / Security Layer"),
        ("html", r"_next/static", "Next.js React Framework"),
        ("html", r"nuxt\.js|__NUXT__", "Nuxt.js Vue Framework"),
        ("html", r"django", "Django Web Framework"),
        ("html", r"rails", "Ruby on Rails Framework")
    ],
    "Frontend Libraries": [
        ("html", r"jquery(?:-|\.min)?\.js", "jQuery Library"),
        ("html", r"react(?:\.production|\.development)?\.js|react-dom", "React Library"),
        ("html", r"vue(?:\.global)?(?:\.min)?\.js", "Vue.js Framework"),
        ("html", r"angular(?:\.min)?\.js|ng-app|ng-version", "Angular Framework"),
        ("html", r"alpine(?:\.min)?\.js|x-data=", "Alpine.js"),
        ("html", r"svelte", "Svelte Frontend Toolchain"),
        ("html", r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js", "Bootstrap CSS Framework"),
        ("html", r"tailwind(?:\.min)?\.css|tailwindcss", "Tailwind CSS Framework"),
        ("html", r"font-awesome|fontawesome", "FontAwesome Icon Set")
    ],
    "Analytics & Trackers": [
        ("html", r"googletagmanager\.com/gtm\.js|gtag\(", "Google Tag Manager"),
        ("html", r"google-analytics\.com/analytics\.js|ga\(", "Google Analytics"),
        ("html", r"connect\.facebook\.net/.*fbevents\.js|fbq\(", "Facebook Pixel"),
        ("html", r"static\.hotjar\.com|hj\(", "Hotjar Analytics"),
        ("html", r"mixpanel\.js|mixpanel", "Mixpanel Analytics")
    ],
    "WAF & CDN": [
        ("server", r"cloudflare", "Cloudflare WAF"),
        ("set-cookie", r"__cfduid", "Cloudflare Tracker"),
        ("headers", r"x-sucuri-id|x-sucuri-cache", "Sucuri WAF"),
        ("headers", r"x-amz-cf-id", "AWS CloudFront CDN"),
        ("headers", r"x-akamai-transformed|x-edgekey", "Akamai CDN / WAF"),
        ("headers", r"x-fastly-request-id", "Fastly CDN"),
        ("headers", r"x-incapsula-sch|incap_ses", "Imperva Incapsula WAF")
    ]
}

def fetch_json(url, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None

def fetch_text(url, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception:
        return None

def get_ip_info(domain):
    print(f"{BLUE}[*]{RESET} Resolving IP, ISP & ASN metadata...")
    url = f"http://ip-api.com/json/{domain}?fields=status,message,country,isp,org,as,query"
    data = fetch_json(url)
    if data and data.get('status') == 'success':
        return {
            'ip': data.get('query', 'N/A'),
            'isp': data.get('isp', 'N/A'),
            'org': data.get('org', 'N/A'),
            'asn': data.get('as', 'N/A'),
            'country': data.get('country', 'N/A')
        }
    else:
        try:
            ip = socket.gethostbyname(domain)
            return {'ip': ip, 'isp': 'N/A', 'org': 'N/A', 'asn': 'N/A', 'country': 'N/A'}
        except Exception:
            return {'ip': 'Could not resolve', 'isp': 'N/A', 'org': 'N/A', 'asn': 'N/A', 'country': 'N/A'}

def get_shodan_db(ip):
    """
    Queries the Shodan InternetDB API. This API is keyless, fast, and passive.
    It returns open ports, hostnames, vulnerabilities (CVEs), and CPEs for an IP.
    """
    if not ip or ip == 'Could not resolve':
        return None
    print(f"{BLUE}[*]{RESET} Querying Shodan InternetDB passive records for IP {ip}...")
    url = f"https://internetdb.shodan.io/{ip}"
    return fetch_json(url, timeout=6)

def get_alienvault_otx(ip):
    """
    Queries AlienVault OTX keyless API for IP security reputation signals.
    """
    if not ip or ip == 'Could not resolve':
        return None
    print(f"{BLUE}[*]{RESET} Querying AlienVault OTX Threat Logs for IP {ip}...")
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    data = fetch_json(url, timeout=6)
    if data:
        reputation = {
            'pulse_count': data.get('pulse_info', {}).get('count', 0),
            'pulses': [p.get('name', '') for p in data.get('pulse_info', {}).get('pulses', [])[:3]],
            'threat_score': data.get('reputation', 0)
        }
        return reputation
    return None

def get_dns_records(domain):
    print(f"{BLUE}[*]{RESET} Resolving standard DNS records...")
    records = {'A': [], 'NS': [], 'MX': [], 'TXT': []}
    for rtype in records.keys():
        url = f"https://dns.google/resolve?name={domain}&type={rtype}"
        data = fetch_json(url)
        if data and 'Answer' in data:
            for answer in data['Answer']:
                records[rtype].append(answer.get('data', ''))
    return records

def get_subdomains_crt(domain):
    print(f"{BLUE}[*]{RESET} Scraping SSL Certificate logs (crt.sh)...")
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    data = fetch_json(url, timeout=12)
    if data:
        for entry in data:
            name_value = entry.get('name_value', '')
            for sub in name_value.split('\n'):
                sub = sub.strip().lower()
                if sub and not sub.startswith('*') and sub.endswith(domain):
                    subdomains.add(sub)
    return subdomains

def get_subdomains_hackertarget(domain):
    print(f"{BLUE}[*]{RESET} Querying HackerTarget DNS index...")
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    data = fetch_text(url, timeout=8)
    if data and "error" not in data.lower():
        for line in data.splitlines():
            parts = line.split(',')
            if parts:
                sub = parts[0].strip().lower()
                if sub.endswith(domain):
                    subdomains.add(sub)
    return subdomains

def analyze_tech_stack(domain):
    print(f"{BLUE}[*]{RESET} Auditing response headers & parsing DOM elements...")
    techs = []
    headers_info = {}
    missing_headers = []
    html = ""
    res_headers = {}
    
    # Check HTTPS, fall back to HTTP
    for proto in ['https://', 'http://']:
        try:
            url = f"{proto}{domain}"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            with urllib.request.urlopen(req, timeout=6, context=ctx) as response:
                html = response.read().decode('utf-8', errors='ignore')
                res_headers = {k.lower(): v for k, v in response.getheaders()}
                break
        except Exception:
            continue
            
    if not res_headers:
        return {'techs': ['Web Server (Offline / No response)'], 'headers': {}, 'missing_headers': [], 'raw_headers': {}}

    # Profile using the Technology Matrix
    # Match headers, set-cookie, and html source
    set_cookie = res_headers.get('set-cookie', '')
    server = res_headers.get('server', '')
    powered_by = res_headers.get('x-powered-by', '')
    
    # Clean output dictionary of headers
    clean_headers = {}
    for k, v in res_headers.items():
        clean_headers[k.title()] = v

    for category, sigs in TECH_SIGNATURES.items():
        for field, pattern, tech_name in sigs:
            matched = False
            if field == "server" and re.search(pattern, server, re.IGNORECASE):
                matched = True
            elif field == "x-powered-by" and re.search(pattern, powered_by, re.IGNORECASE):
                matched = True
            elif field == "set-cookie" and re.search(pattern, set_cookie, re.IGNORECASE):
                matched = True
            elif field == "headers":
                # Check if key pattern is present in header names
                for h_name in res_headers.keys():
                    if re.search(pattern, h_name, re.IGNORECASE):
                        matched = True
            elif field == "html" and html:
                if re.search(pattern, html, re.IGNORECASE):
                    matched = True
            
            if matched:
                techs.append(f"{category} | {tech_name}")

    # Tech deduplication
    techs = sorted(list(set(techs)))

    # Missing Security Headers Checks
    security_headers = {
        'content-security-policy': 'Content-Security-Policy (Restricts resource load boundaries)',
        'strict-transport-security': 'Strict-Transport-Security (Enforces HTTPS connection)',
        'x-frame-options': 'X-Frame-Options (Protects against Clickjacking)',
        'x-content-type-options': 'X-Content-Type-Options (Prevents MIME sniffing)',
        'referrer-policy': 'Referrer-Policy (Controls referrer leakage)'
    }
    for header, desc in security_headers.items():
        if header not in res_headers:
            missing_headers.append(desc)

    return {
        'techs': techs,
        'headers': clean_headers,
        'missing_headers': missing_headers
    }

def get_vulnerabilities(techs):
    print(f"{BLUE}[*]{RESET} Reviewing vulnerability lists & exploit vectors...")
    vulns = []
    searchsploit_path = shutil.which("searchsploit")
    
    for tech in techs:
        # Tech string format is "Category | TechName Version"
        # Extract the technology and version
        parts = tech.split('|')
        if len(parts) > 1:
            tech_term = parts[1].strip()
        else:
            tech_term = tech.strip()
            
        # Filter terms that contain potential version numbers (e.g., Apache/2.4.41 or WordPress 5.8)
        search_query = tech_term.replace('/', ' ')
        
        # We only check if it contains letters and version info
        version_match = re.search(r'\d+\.\d+', search_query)
        if not version_match:
            continue
            
        # 1. Search local searchsploit database if on Kali
        if searchsploit_path:
            try:
                cmd = [searchsploit_path, "--json", search_query]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.stdout:
                    res_json = json.loads(result.stdout)
                    results = res_json.get('RESULTS_EXPLOIT', [])
                    if results:
                        vulns.append(f"\n{RED}[CRITICAL]{RESET} Searchsploit matched exploits for '{search_query}':")
                        for res in results[:2]:
                            vulns.append(f"  - {res.get('Title', '')} (Exploit Path: {res.get('Path', '')})")
                        continue
            except Exception:
                pass

        # 2. Fallback to circl.lu online CVE catalog API
        parts_query = search_query.split()
        software = parts_query[0]
        version = parts_query[1] if len(parts_query) > 1 else ''
        
        # Simple clean up of software name
        software = re.sub(r'[^a-zA-Z0-9]', '', software)
        
        url = f"https://cve.circl.lu/api/search/{software}"
        api_data = fetch_json(url)
        if api_data:
            cve_matches = []
            for item in api_data:
                summary = item.get('summary', '')
                if version in summary:
                    cve_id = item.get('id', '')
                    cvss = item.get('cvss', 'N/A')
                    cve_matches.append(f"  - {RED}{cve_id}{RESET} (CVSS: {cvss}) - {summary[:90]}...")
            if cve_matches:
                vulns.append(f"\n{RED}[CRITICAL]{RESET} Public CVE matches for '{search_query}':")
                vulns.extend(cve_matches[:3])
                
    return vulns

def run(domain):
    print(f"\n{BOLD}{CYAN}=== Launching ThreatByt Passive Recon Engine ==={RESET}")
    
    # Fetch Base Host Info
    ip_data = get_ip_info(domain)
    target_ip = ip_data.get('ip')
    
    # Query Shodan InternetDB
    shodan_data = get_shodan_db(target_ip)
    
    # Query AlienVault OTX
    otx_data = get_alienvault_otx(target_ip)
    
    # Fetch DNS Records
    dns_data = get_dns_records(domain)
    
    # Harvest Subdomains
    subdomains = set()
    try:
        subdomains.update(get_subdomains_crt(domain))
    except Exception:
        pass
    try:
        subdomains.update(get_subdomains_hackertarget(domain))
    except Exception:
        pass
    subdomains_list = sorted(list(subdomains))
    
    # Audit Tech stack & headers
    tech_data = analyze_tech_stack(domain)
    
    # Query CVE exploits
    vulns_list = get_vulnerabilities(tech_data.get('techs', []))
    
    # Append Shodan CVEs if present
    shodan_vulns = []
    shodan_ports = []
    if shodan_data:
        shodan_ports = shodan_data.get('ports', [])
        shodan_cves = shodan_data.get('vulns', [])
        if shodan_cves:
            shodan_vulns.append(f"\n{RED}[CRITICAL]{RESET} Passive Vulns found in Shodan database:")
            for cve in shodan_cves[:4]:
                shodan_vulns.append(f"  - {cve} (Reported via passive port checks)")
    
    # Build Console Outputs & Reports
    report = []
    
    # 1. Base Target Profile
    print(f"\n{GREEN}[+] Target Information:{RESET}")
    report.append("--- TARGET BASE PROFILING ---")
    ip_str = f"Resolved IP: {target_ip}"
    asn_str = f"ASN / ISP: {ip_data['asn']} ({ip_data['isp']})"
    org_str = f"Organization: {ip_data['org']}"
    country_str = f"Geographic Origin: {ip_data['country']}"
    print(f"  [*] {ip_str}\n  [*] {asn_str}\n  [*] {org_str}\n  [*] {country_str}")
    report.extend([f"  {ip_str}", f"  {asn_str}", f"  {org_str}", f"  {country_str}\n"])
    
    # 2. AlienVault logs
    if otx_data and otx_data['pulse_count'] > 0:
        print(f"  {YELLOW}[!] Threat Intel Alert (AlienVault OTX):{RESET}")
        report.append("  Threat Intel Alerts (AlienVault OTX):")
        print(f"    - Threat Pulses Found: {otx_data['pulse_count']}")
        report.append(f"    - Threat Pulses Found: {otx_data['pulse_count']}")
        for pulse in otx_data['pulses']:
            print(f"    - Indicator Flag: {pulse}")
            report.append(f"    - Indicator Flag: {pulse}")
        report.append("")
        
    # 3. Passive Open Ports (Shodan)
    print(f"\n{GREEN}[+] Passive Port Intel (Shodan DB):{RESET}")
    report.append("--- PASSIVE OPEN PORTS (SHODAN) ---")
    if shodan_ports:
        ports_line = f"Open Ports: {', '.join(map(str, sorted(shodan_ports)))}"
        print(f"  [*] {ports_line}")
        report.append(f"  {ports_line}")
    else:
        print("  [*] No passive port details found in Shodan database.")
        report.append("  No passive port details found in Shodan database.")
    report.append("")

    # 4. DNS records
    print(f"\n{GREEN}[+] DNS Architecture:{RESET}")
    report.append("--- DNS ARCHITECTURE ---")
    for rtype, records in dns_data.items():
        if records:
            print(f"  {BOLD}{rtype} Records:{RESET}")
            report.append(f"  {rtype} Records:")
            for record in records:
                print(f"    - {record}")
                report.append(f"    - {record}")
        else:
            print(f"  {BOLD}{rtype} Records:{RESET} None found")
            report.append(f"  {rtype} Records: None")
    report.append("")

    # 5. Technology Stack
    print(f"\n{GREEN}[+] Technology Profile:{RESET}")
    report.append("--- TECHNOLOGY PROFILING ---")
    if tech_data['techs']:
        for tech in tech_data['techs']:
            print(f"  [*] {tech}")
            report.append(f"  - {tech}")
    else:
        print("  [*] No technology fingerprints detected")
        report.append("  - No technology fingerprints detected")
        
    if tech_data['missing_headers']:
        print(f"\n  {YELLOW}[!] Missing Security Headers:{RESET}")
        report.append("\n  Missing Security Headers:")
        for header in tech_data['missing_headers']:
            print(f"    - {header}")
            report.append(f"    - {header}")
    report.append("")

    # 6. Vulnerabilities Map
    print(f"\n{GREEN}[+] Vulnerability Correlations:{RESET}")
    report.append("--- VULNERABILITY MAP ---")
    has_vulns = False
    
    if vulns_list:
        has_vulns = True
        for vuln in vulns_list:
            print(vuln)
            report.append(vuln.replace(RED, '').replace(RESET, '').replace(GREEN, ''))
            
    if shodan_vulns:
        has_vulns = True
        for vuln in shodan_vulns:
            print(vuln)
            report.append(vuln.replace(RED, '').replace(RESET, '').replace(GREEN, ''))
            
    if not has_vulns:
        print("  [*] No vulnerabilities associated with technology versions found passively.")
        report.append("  - No vulnerabilities associated with tech versions found passively.")
    report.append("")

    # 7. Subdomains list
    print(f"\n{GREEN}[+] Passive Subdomain Harvest ({len(subdomains_list)} hosts):{RESET}")
    report.append(f"--- PASSIVE SUBDOMAINS HARVESTED ({len(subdomains_list)}) ---")
    if subdomains_list:
        for sub in subdomains_list[:15]:
            print(f"  [+] {sub}")
        if len(subdomains_list) > 15:
            print(f"  ... and {len(subdomains_list) - 15} more subdomains (written to reports)")
        for sub in subdomains_list:
            report.append(f"  - {sub}")
    else:
        print("  [*] No subdomains found passively")
        report.append("  - No subdomains found passively")
    report.append("")

    # Compile structured data to pass to HTML reports generator
    structured_data = {
        'ip': target_ip,
        'base_info': ip_data,
        'dns_info': dns_data,
        'shodan_ports': shodan_ports,
        'otx_threats': otx_data,
        'tech_stack': tech_data['techs'],
        'headers': tech_data['headers'],
        'missing_headers': tech_data['missing_headers'],
        'vulns': [v.replace(RED, '').replace(RESET, '').replace(GREEN, '').strip() for v in vulns_list + shodan_vulns if 'matches' not in v.lower()],
        'subdomains': subdomains_list
    }

    return {
        'subdomains': subdomains_list,
        'report': "\n".join(report),
        'structured_data': structured_data
    }
