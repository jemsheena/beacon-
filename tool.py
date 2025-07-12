import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin
import pyfiglet
from termcolor import colored
from time import sleep
import random
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import socket
import subprocess
from colorama import init, Fore

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.31.0",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "sqlmap/1.5.2#stable"
]

FAKE_IPS = [
    "127.0.0.1", "192.168.1.1", "10.0.0.5", "8.8.8.8", "1.1.1.1"
]

CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("test", "123456")
]

LOG_SENSITIVE_PATHS = [
    "/admin", "/.env", "/.git/config", "/config.php",
    "/server-status", "/wp-login.php", "/phpinfo.php",
    "/etc/passwd", "/debug", "/login?user=admin"
]

HIDDEN_PATHS = ["/hidden", "/private", "/secret"]

RESULT_FILE = "webtester_a07_results.txt"

COMMON_ADMIN_PATHS = [
    '/admin', '/administrator', '/admin/login', '/login', '/dashboard',
    '/manage', '/user/admin', '/cpanel', '/backend', '/controlpanel'
]

def log_result(message):
    with open(RESULT_FILE, "a") as f:
        f.write(f"{message}\n")

def test_single_credential(login_url, username, password):
    payload = {"username": username, "password": password}
    try:
        r = requests.post(login_url, data=payload, timeout=2)
        if ("welcome" in r.text.lower() or "dashboard" in r.text.lower() or
            "logout" in r.text.lower() or r.status_code in [200, 302]):
            return f"    [!] Weak credentials found: {username}:{password}"
    except RequestException:
        return None
    return None

def test_authentication(url, login_path="/login", max_threads=100):
    print("\n[+] Testing for Weak Authentication (OWASP A07)...")
    log_result("\n[+] Testing for Weak Authentication (OWASP A07)...")
    login_url = urljoin(url, login_path)
    success = False

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_creds = {
            executor.submit(test_single_credential, login_url, username, password): (username, password)
            for username, password in CREDENTIALS
        }

        for future in as_completed(future_to_creds):
            result = future.result()
            if result:
                print(result)
                log_result(result)
                success = True
                break

    if not success:
        msg = "    [OK] No weak/default credentials detected."
        print(msg)
        log_result(msg)
    else:
        print("\n[!!] The website is VULNERABLE to weak/default credential attacks (OWASP A07).")
        log_result("\n[!!] The website is VULNERABLE to weak/default credential attacks (OWASP A07).")

def test_username_enumeration(url, login_path="/login"):
    print("\n[+] Testing for Username Enumeration...")
    known_user = "admin"
    fake_user = "notarealuser999"
    password = "wrongpass"

    real_response = requests.post(urljoin(url, login_path), data={"username": known_user, "password": password})
    fake_response = requests.post(urljoin(url, login_path), data={"username": fake_user, "password": password})

    if real_response.text != fake_response.text:
        msg = "    [!] Possible Username Enumeration: Different responses for valid and invalid usernames."
        print(msg)
        log_result(msg)
    else:
        msg = "    [OK] No obvious username enumeration behavior."
        print(msg)
        log_result(msg)

def test_rate_limiting(url, login_path="/login"):
    print("\n[+] Testing for Rate Limiting...")
    username = "admin"
    password = "wrongpass"
    login_url = urljoin(url, login_path)
    start = time.time()
    for _ in range(20):
        try:
            requests.post(login_url, data={"username": username, "password": password})
        except:
            pass
    elapsed = time.time() - start
    if elapsed < 3:
        msg = "    [!] No rate limiting detected: 20 rapid attempts completed in under 3s."
        print(msg)
        log_result(msg)
    else:
        msg = "    [OK] Some rate limiting behavior detected."
        print(msg)
        log_result(msg)

def test_bruteforce_lockout(url, login_path="/login"):
    print("\n[+] Testing for Account Lockout Mechanism...")
    username = "admin"
    password = "wrongpass"
    locked = False
    for attempt in range(1, 11):
        r = requests.post(urljoin(url, login_path), data={"username": username, "password": password})
        if "account locked" in r.text.lower():
            msg = f"    [!] Account lockout detected after {attempt} attempts."
            print(msg)
            log_result(msg)
            locked = True
            break
    if not locked:
        msg = "    [!] No account lockout mechanism detected."
        print(msg)
        log_result(msg)

def check_mfa_support(url):
    print("\n[+] Checking for Multi-Factor Authentication (MFA) Support...")
    try:
        r = requests.get(url, timeout=5)
        if any(keyword in r.text.lower() for keyword in ["2fa", "mfa", "otp", "authenticator"]):
            msg = "    [OK] MFA-related keywords found on site."
            print(msg)
            log_result(msg)
        else:
            msg = "    [!] No indication of MFA support found on main page."
            print(msg)
            log_result(msg)
    except Exception as e:
        msg = f"    [ERROR] Failed to check MFA support: {e}"
        print(msg)
        log_result(msg)

def run_a07_scan():
    banner = pyfiglet.figlet_format("WebTester - A07")
    colored_banner = colored(banner, color="cyan")
    print(colored_banner)

    with open(RESULT_FILE, "w") as f:
        f.write(f"=== A07 Authentication Test Report ===\nGenerated on: {datetime.datetime.now()}\n\n")

    target = input("Enter target URL (e.g., http://example.com): ").strip().rstrip('/')

    try:
        print("\n[+] Connecting to target...")
        response = requests.get(target, timeout=5)
        print(f"    [Status] {response.status_code} OK")
        log_result(f"[+] Connected to {target} - Status {response.status_code}")

        test_authentication(target)
        test_username_enumeration(target)
        test_rate_limiting(target)
        test_bruteforce_lockout(target)
        check_mfa_support(target)

        print(f"\n[✔] Scan complete. Results saved to: {RESULT_FILE}")

    except RequestException as e:
        msg = f"[ERROR] Failed to connect to {target}: {e}"
        print(msg)
        log_result(msg)

# --- Utility Functions ---
def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def extract_domain(url):
    return urlparse(url).netloc

def generate_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random.choice(FAKE_IPS),
        "Content-Type": "application/x-www-form-urlencoded"
    }

# --- Test Functions ---
def test_security_headers(url):
    print("\n🔐 Checking for Missing Security Headers...")
    headers_to_check = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Referrer-Policy"
    ]
    try:
        res = requests.get(url, timeout=5)
        for header in headers_to_check:
            if header not in res.headers:
                print(f"[-] Missing: {header}")
            else:
                print(f"[+] Present: {header}")
    except Exception as e:
        print(f"[!] Header check failed: {e}")

def test_http_methods(url):
    print("\n🔄 Checking Allowed HTTP Methods...")
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"]
    for method in methods:
        try:
            res = requests.request(method, url, timeout=5)
            if res.status_code not in [405, 501]:
                print(f"[!] {method} allowed (status {res.status_code})")
            else:
                print(f"[+] {method} blocked (status {res.status_code})")
        except:
            print(f"[!] Failed method test: {method}")

def test_directory_listing(url):
    print("\n📂 Checking for Open Directory Listings...")
    paths = ["/uploads/", "/images/", "/admin/", "/css/", "/phpmyadmin/"]
    for path in paths:
        full_url = urljoin(url, path)
        try:
            res = requests.get(full_url, timeout=5)
            if "Index of" in res.text:
                print(f"[!] Directory listing enabled at: {full_url}")
        except:
            pass

def test_cors(url):
    print("\n🌍 Checking CORS Configuration...")
    headers = {"Origin": "http://evil.com"}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        acao = res.headers.get("Access-Control-Allow-Origin")
        if acao == "*" or acao == "http://evil.com":
            print(f"[!] Misconfigured CORS: {acao}")
        else:
            print(f"[+] CORS OK: {acao or 'Not set'}")
    except:
        print("[!] Failed CORS check")

def test_error_messages(url):
    print("\n⚠ Checking for Verbose Error Pages...")
    test_url = urljoin(url, "/thispagedoesnotexist")
    try:
        res = requests.get(test_url, timeout=5)
        if any(term in res.text.lower() for term in ["exception", "traceback", "fatal error", "apache", "nginx", "php"]):
            print("[!] Tech stack or stack trace found in error!")
        else:
            print("[+] Error page is generic.")
    except:
        print("[!] Could not check error page.")

def test_admin_panels(url):
    print("\n🚪 Checking for Open Admin Panels...")
    admin_paths = ["/admin", "/phpmyadmin", "/cpanel", "/config", "/administrator"]
    for path in admin_paths:
        full_url = urljoin(url, path)
        try:
            res = requests.get(full_url, timeout=5)
            if res.status_code in [200, 401, 403]:
                print(f"[!] Potential admin panel at: {full_url} (status {res.status_code})")
        except:
            pass

def test_integrity_of_scripts(url):
    print("\n[SOFTWARE AND DATA INTEGRITY CHECK]")
    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = soup.find_all("script")
        origin_domain = extract_domain(url)
        external_scripts = []
        for script in scripts:
            src = script.get("src")
            if src:
                script_domain = extract_domain(src)
                is_external = script_domain != "" and script_domain != origin_domain
                integrity = script.get("integrity")
                versioned = "v=" in src or "version=" in src or any(x in src for x in ["hash", "sha"])
                print(f"\nScript: {src}")
                if is_external:
                    print("Source: External")
                    if not integrity:
                        print("Warning: No integrity attribute – Possible source integrity risk.")
                    else:
                        print("Integrity attribute present – Integrity protection enabled.")
                else:
                    print("Source: Local script")
                if not versioned:
                    print("Warning: No version/hash in script URL – Hard to verify integrity.")
                else:
                    print("Script appears versioned – Better for caching/integrity.")
                external_scripts.append((src, integrity))
        if not external_scripts:
            print("No external scripts found.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch page: {e}")

def test_logging_monitoring(url):
    suspicious_success_count = 0
    total_tests = 0

    print(colored("\n[*] Brute-force Simulation:", "yellow"))
    login_url = urljoin(url, "/login")
    for user, pwd in CREDENTIALS:
        data = {"username": user, "password": pwd}
        try:
            r = requests.post(login_url, headers=generate_headers(), data=data, timeout=5)
            print(f"[+] Tried {user}:{pwd} => Status: {r.status_code}")
            if r.status_code in [200, 302]:
                suspicious_success_count += 1
            total_tests += 1
            sleep(1)
        except Exception as e:
            print(colored(f"[!] Error: {e}", "red"))

    print(colored("\n[*] Scanning Log-Sensitive Endpoints:", "yellow"))
    for path in LOG_SENSITIVE_PATHS:
        test_url = urljoin(url, path)
        try:
            r = requests.get(test_url, headers=generate_headers(), timeout=5)
            print(f"[+] Accessed {test_url} => Status: {r.status_code}")
            if r.status_code in [200, 403, 404]:
                suspicious_success_count += 1
            total_tests += 1
            sleep(0.5)
        except Exception as e:
            print(colored(f"[!] Error accessing {path}: {e}", "red"))

    print(colored("\n[*] Probing Hidden/Unlisted Paths:", "yellow"))
    for path in HIDDEN_PATHS:
        test_url = urljoin(url, path)
        try:
            r = requests.get(test_url, headers=generate_headers(), timeout=5)
            print(f"[+] Accessed {test_url} => Status: {r.status_code}")
            if r.status_code in [200, 403, 404]:
                suspicious_success_count += 1
            total_tests += 1
        except Exception as e:
            print(colored(f"[!] Error: {e}", "red"))

    print(colored("\n[*] Final Analysis", "cyan"))
    print(f"[+] Total suspicious requests sent: {total_tests}")
    print(f"[+] Requests that succeeded or were not blocked: {suspicious_success_count}")

    if suspicious_success_count == total_tests:
        print(colored("[!] Website is likely VULNERABLE to OWASP A09: Logging and Monitoring Failures.", "red"))
    elif suspicious_success_count >= total_tests * 0.6:
        print(colored("[!] Website is POSSIBLY VULNERABLE to OWASP A09: Logging and Monitoring Failures.", "yellow"))
    else:
        print(colored("[+] Website appears to have SOME detection and blocking mechanisms in place.", "green"))

def scan_ssl_ciphers(domain):
    print(f"\n[+] Scanning SSL/TSL ciphers for {domain}...\n")
    try:
        result = subprocess.run(
            ["nmap", "-p", "443", "--script", "ssl-enum-ciphers", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("[!] Error running nmap:")
            print(result.stderr)
    except FileNotFoundError:
        print("[!] nmap is not installed or not found in PATH.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

def check_ssrf(url):
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        found_url = None
        for param, values in query.items():
            for value in values:
                if value.startswith("http://") or value.startswith("https://"):
                    found_url = value
                    break
        if not found_url:
            print("[-] No SSRF-like parameter found in the URL.")
            return
        print(f"[+] Found potential SSRF target: {found_url}")
        inner_host = urlparse(found_url).hostname
        ip = socket.gethostbyname(inner_host)
        print(f"[+] Resolved IP: {ip}")
        if is_private_ip(ip):
            print(f"[!] Potential SSRF risk: IP address {ip} is internal/private.")
        else:
            print(f"[-] IP address {ip} is public. No obvious SSRF risk.")
    except Exception as e:
        print(f"[ERROR] Could not analyze URL: {e}")

def is_private_ip(ip):
    private_blocks = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('169.254.0.0', '169.254.255.255')
    ]
    ip_parts = list(map(int, ip.split('.')))
    ip_val = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
    for start, end in private_blocks:
        start_val = sum(int(part) << (8 * (3 - i)) for i, part in enumerate(start.split('.')))
        end_val = sum(int(part) << (8 * (3 - i)) for i, part in enumerate(end.split('.')))
        if start_val <= ip_val <= end_val:
            return True
    return False

def test_vulnerable_components(url):
    init(autoreset=True)

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnScanner/4.1",
        "Accept": "text/html,application/xhtml+xml"
    }

    VULNERABLE_LIBS = {
        "jquery": {
            "1.6.4": "CVE-2015-9251",
            "1.7.2": "CVE-2015-9251",
            "1.9.1": "CVE-2019-11358",
            "3.0.0": "CVE-2020-11023"
        },
        "bootstrap": {
            "3.3.6": "CVE-2016-10735",
            "3.3.7": "CVE-2018-14041",
            "4.1.1": "CVE-2018-14040"
        },
        "angularjs": {
            "1.2.28": "CVE-2018-11654",
            "1.6.9": "CVE-2019-10768"
        },
        "react": {
            "16.0.0": "CVE-2020-15136"
        },
        "vue": {
            "2.5.17": "CVE-2019-10742"
        },
        "fontawesome": {
            "4.7.0": "CVE-2019-10744"
        }
    }

    DEPRECATED_BACKENDS = {
        "apache/2.2": "End-of-life, vulnerable",
        "php/5.4": "End-of-life, vulnerable",
        "php/5.6": "End-of-life, vulnerable"
    }

    TRUSTED_CDNS = [
        "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
        "unpkg.com", "fonts.googleapis.com"
    ]

    LIB_PATTERN = re.compile(r'(jquery|bootstrap|angularjs|react|vue|fontawesome)[-/\. ]?(\d+\.\d+(?:\.\d+|[a-zA-Z0-9.\-]+)?)', re.IGNORECASE)
    INLINE_VERSION_PATTERN = re.compile(r'(jquery|angular|react|vue)[^a-z0-9]{1,5}(?:version|ver)?[^a-z0-9]{1,5}["\']?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)

    visited = set()
    results = set()
    MAX_PAGES = 30
    INCLUDE_WARNINGS = False

    def normalize_version(ver):
        parts = re.split(r'[^0-9a-zA-Z]', ver)
        while len(parts) < 3:
            parts.append('0')
        return '.'.join(parts[:3])

    def check_lib(lib, version):
        lib = lib.lower()
        norm_ver = normalize_version(version)
        return VULNERABLE_LIBS.get(lib, {}).get(norm_ver)

    def check_sri(tag):
        if tag.name not in ['script', 'link']:
            return None
        if tag.has_attr('src') or tag.has_attr('href'):
            if 'cdn' in (tag.get('src') or tag.get('href')) and not tag.has_attr('integrity'):
                return "[!] Missing SRI for CDN resource"
        return None

    def check_untrusted_origin(url):
        domain = urlparse(url).netloc.lower()
        return all(t not in domain for t in TRUSTED_CDNS)

    def scan_html(base_url, html):
        soup = BeautifulSoup(html, 'html.parser')

        for tag in soup.find_all(['script', 'link']):
            src = tag.get('src') or tag.get('href')
            if not src:
                continue
            full_url = urljoin(base_url, src)

            match = LIB_PATTERN.search(full_url)
            if match:
                lib, ver = match.groups()
                cve = check_lib(lib, ver)
                if cve:
                    results.add((lib, ver, cve, full_url))

            sri_warn = check_sri(tag)
            if sri_warn:
                results.add(("sri", "N/A", sri_warn, full_url))

            if INCLUDE_WARNINGS and check_untrusted_origin(full_url):
                results.add(("cdn", "N/A", "[!] Untrusted CDN origin", full_url))

        for script in soup.find_all("script"):
            if script.string:
                matches = INLINE_VERSION_PATTERN.findall(script.string)
                for lib, ver in matches:
                    cve = check_lib(lib, ver)
                    if cve:
                        results.add((lib, ver, cve, "inline-script"))

    def fingerprint_server(headers, url):
        for header in ["Server", "X-Powered-By"]:
            value = headers.get(header, "").lower()
            for dep in DEPRECATED_BACKENDS:
                if dep in value:
                    results.add(("backend", "N/A", f"Outdated backend: {value}", url))

    def crawl(url, domain):
        if url in visited or len(visited) >= MAX_PAGES:
            return
        visited.add(url)
        try:
            print(f"[*] Scanning: {url}")
            r = requests.get(url, headers=HEADERS, timeout=10)
            if 'text/html' not in r.headers.get('Content-Type', ''):
                return

            scan_html(url, r.text)
            fingerprint_server(r.headers, url)

            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href'])
                if urlparse(link).netloc == domain:
                    crawl(link, domain)
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning {url}: {e}")

    domain = urlparse(url).netloc

    print(f"\n[+] Starting OWASP A06 scan on: {url}\n")
    try:
        requests.get(url, headers=HEADERS, timeout=10)
    except Exception as e:
        print(f"{Fore.RED}[!] Initial request failed: {e}")
        return

    crawl(url, domain)

    print("\n[+] Scan complete.")
    if not results:
        print("[+] No vulnerabilities found.")
    else:
        print("[!] Vulnerabilities or warnings detected:")
        for res in results:
            print(f" - {res[0]}: {res[2]} (URL: {res[3]})")

class SecurityScanner:
    def __init__(self, target):
        self.target = target if target.endswith("/") else target + "/"

    def check_security_headers(self):
        print("\n🔐 Checking for Missing Security Headers...")
        headers_to_check = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]
        try:
            res = requests.get(self.target, timeout=5)
            for header in headers_to_check:
                if header not in res.headers:
                    print(f"[-] Missing: {header}")
                else:
                    print(f"[+] Present: {header}")
        except Exception as e:
            print(f"[!] Header check failed: {e}")

    def check_http_methods(self):
        print("\n🔄 Checking Allowed HTTP Methods...")
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"]
        for method in methods:
            try:
                res = requests.request(method, self.target, timeout=5)
                if res.status_code not in [405, 501]:
                    print(f"[!] {method} allowed (status {res.status_code})")
                else:
                    print(f"[+] {method} blocked (status {res.status_code})")
            except:
                print(f"[!] Failed method test: {method}")

    def check_directory_listing(self):
        print("\n📂 Checking for Open Directory Listings...")
        paths = ["/uploads/", "/images/", "/admin/", "/css/", "/phpmyadmin/"]
        for path in paths:
            url = urljoin(self.target, path)
            try:
                res = requests.get(url, timeout=5)
                if "Index of" in res.text:
                    print(f"[!] Directory listing enabled at: {url}")
            except:
                pass

    def check_cors(self):
        print("\n🌍 Checking CORS Configuration...")
        headers = {"Origin": "http://evil.com"}
        try:
            res = requests.get(self.target, headers=headers, timeout=5)
            acao = res.headers.get("Access-Control-Allow-Origin")
            if acao == "*" or acao == "http://evil.com":
                print(f"[!] Misconfigured CORS: {acao}")
            else:
                print(f"[+] CORS OK: {acao or 'Not set'}")
        except:
            print("[!] Failed CORS check")

    def check_error_messages(self):
        print("\n⚠ Checking for Verbose Error Pages...")
        test_url = urljoin(self.target, "/thispagedoesnotexist")
        try:
            res = requests.get(test_url, timeout=5)
            if any(term in res.text.lower() for term in ["exception", "traceback", "fatal error", "apache", "nginx", "php"]):
                print("[!] Tech stack or stack trace found in error!")
            else:
                print("[+] Error page is generic.")
        except:
            print("[!] Could not check error page.")

    def check_admin_panels(self):
        print("\n🚪 Checking for Open Admin Panels...")
        admin_paths = ["/admin", "/phpmyadmin", "/cpanel", "/config", "/administrator"]
        for path in admin_paths:
            full_url = urljoin(self.target, path)
            try:
                res = requests.get(full_url, timeout=5)
                if res.status_code in [200, 401, 403]:
                    print(f"[!] Potential admin panel at: {full_url} (status {res.status_code})")
            except:
                pass

    def run_all(self):
        self.check_security_headers()
        self.check_http_methods()
        self.check_directory_listing()
        self.check_cors()
        self.check_error_messages()
        self.check_admin_panels()

def check_insecure_design(base_url):
    print(f"Scanning {base_url} for exposed admin panels and insecure design...")
    found = False
    for path in COMMON_ADMIN_PATHS:
        url = base_url.rstrip('/') + path
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                print(f"[!] Potential insecure design: Publicly accessible {url}")
                found = True
        except Exception:
            continue
    if found:
        print("\nVulnerability is present.")
    else:
        print("\nVulnerability is not present.")

def main_menu():
    banner = pyfiglet.figlet_format("WebTester")
    print(colored(banner, "blue"))
    print("Select a test to run (OWASP Top 10):")
    print("1. Identification & Authentication Failures (A07)")
    print("2. Insecure Design (A04)")
    print("3. Security Logging & Monitoring Failures (A09)")
    print("4. Server-Side Request Forgery (SSRF) (A10)")
    print("5. Security Misconfiguration (A05)")
    print("6. Broken Access Control (A01)")
    print("7. Cryptographic Failures (A02)")
    print("8. Vulnerable & Outdated Components (A06)")
    print("9. Software and Data Integrity Failures (A08)")
    print("10. Run ALL checks and save output")
    print("0. Exit")

def run_all_scans():
    output_file = "webtester_full_scan.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        def log(msg):
            print(msg)
            f.write(msg + "\n")

        banner = pyfiglet.figlet_format("WebTester - Full Scan")
        log(colored(banner, "magenta"))
        log(f"Scan started at: {datetime.datetime.now()}\n")

        # 1. Authentication
        log("\n=== [1] Identification & Authentication Failures (A07) ===")
        target = input("Enter target URL for authentication tests: ").strip()
        try:
            test_authentication(target)
            test_username_enumeration(target)
            test_rate_limiting(target)
            test_bruteforce_lockout(target)
            check_mfa_support(target)
        except Exception as e:
            log(f"[ERROR] Auth tests: {e}")

        # 2. Insecure Design
        log("\n=== [2] Insecure Design (A04) ===")
        url = input("Enter target URL for insecure design: ").strip()
        try:
            check_insecure_design(url)
        except Exception as e:
            log(f"[ERROR] Insecure Design: {e}")

        # 3. Logging & Monitoring
        log("\n=== [3] Security Logging & Monitoring Failures (A09) ===")
        url = input("Enter target URL for logging/monitoring: ").strip()
        try:
            test_logging_monitoring(url)
        except Exception as e:
            log(f"[ERROR] Logging/Monitoring: {e}")

        # 4. SSRF
        log("\n=== [4] Server-Side Request Forgery (A10) ===")
        url = input("Enter SSRF test URL: ").strip()
        try:
            check_ssrf(url)
        except Exception as e:
            log(f"[ERROR] SSRF: {e}")

        # 5. Security Misconfiguration
        log("\n=== [5] Security Misconfiguration (A05) ===")
        url = input("Enter target URL for misconfiguration: ").strip()
        try:
            scanner = SecurityScanner(normalize_url(url))
            scanner.run_all()
        except Exception as e:
            log(f"[ERROR] Misconfiguration: {e}")

        # 6. Broken Access Control
        log("\n=== [6] Broken Access Control (A01) ===")
        base_url = input("Enter base URL for BAC (e.g. https://example.com/api/user): ").strip()
        start_id = int(input("Enter start ID (default 1): ") or "1")
        end_id = int(input("Enter end ID (default 10): ") or "10")
        token = input("Enter Authorization token (optional): ").strip() or None
        try:
            # BAC check: enumerate user IDs and check for access control issues
            for user_id in range(start_id, end_id + 1):
                url = f"{base_url.rstrip('/')}/{user_id}"
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                try:
                    resp = requests.get(url, headers=headers, timeout=5)
                    print(f"[BAC] Checked {url} => Status: {resp.status_code}")
                    if resp.status_code == 200:
                        print(f"[!] Possible Broken Access Control at {url}")
                except Exception as e:
                    print(f"[ERROR] BAC check for {url}: {e}")
        except Exception as e:
            log(f"[ERROR] BAC: {e}")

        # 7. Cryptographic Failures
        log("\n=== [7] Cryptographic Failures (A02) ===")
        domain = input("Enter domain name for SSL scan: ").strip()
        try:
            scan_ssl_ciphers(domain)
        except Exception as e:
            log(f"[ERROR] SSL Scan: {e}")

        # 8. Vulnerable Components
        log("\n=== [8] Vulnerable & Outdated Components (A06) ===")
        url = input("Enter target URL for vulnerable components: ").strip()
        try:
            test_vulnerable_components(url)
        except Exception as e:
            log(f"[ERROR] Vulnerable Components: {e}")

        # 9. Software/Data Integrity
        log("\n=== [9] Software and Data Integrity Failures (A08) ===")
        url = input("Enter target URL for integrity check: ").strip()
        try:
            test_integrity_of_scripts(url)
        except Exception as e:
            log(f"[ERROR] Integrity Check: {e}")

        log(f"\nScan finished at: {datetime.datetime.now()}")
        log(f"Results saved to: {output_file}")

# --- Update main() ---
def main():
    while True:
        main_menu()
        choice = input("Enter your choice: ").strip()
        if choice == "0":
            print("Exiting.")
            break
        elif choice == "1":
            run_a07_scan()
        elif choice == "2":
            url = input("Enter the website URL (e.g., https://example.com): ").strip()
            check_insecure_design(url)
        elif choice == "3":
            url = input("Enter the base URL (e.g., https://example.com): ").strip()
            test_logging_monitoring(url)
        elif choice == "4":
            url = input("Enter target URL with SSRF parameter: ").strip()
            check_ssrf(url)
        elif choice == "5":
            url = normalize_url(input("Enter target URL: ").strip())
            scanner = SecurityScanner(url)
            scanner.run_all()
        elif choice == "6":
            base_url = input("Enter base URL (e.g. https://example.com/api/user): ").strip()
            start_id = int(input("Enter start ID (default 1): ") or "1")
            end_id = int(input("Enter end ID (default 10): ") or "10")
            token = input("Enter Authorization token (optional): ").strip() or None
            # BAC check: enumerate user IDs and check for access control issues
            for user_id in range(start_id, end_id + 1):
                url = f"{base_url.rstrip('/')}/{user_id}"
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                try:
                    resp = requests.get(url, headers=headers, timeout=5)
                    print(f"[BAC] Checked {url} => Status: {resp.status_code}")
                    if resp.status_code == 200:
                        print(f"[!] Possible Broken Access Control at {url}")
                except Exception as e:
                    print(f"[ERROR] BAC check for {url}: {e}")
        elif choice == "7":
            domain = input("Enter domain name (e.g. example.com): ").strip()
            scan_ssl_ciphers(domain)
        elif choice == "8":
            url = normalize_url(input("Enter target URL: ").strip())
            test_vulnerable_components(url)
        elif choice == "9":
            url = normalize_url(input("Enter the website URL (with or without http/https): ").strip())
            test_integrity_of_scripts(url)
        elif choice == "10":
            run_all_scans()
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
# This script is designed to be run as a standalone tool.
# Ensure you have the required libraries installed: requests, beautifulsoup4, pyfiglet, termcolor, nmap (for SSL scanning).
# You can install them using pip: