#!/usr/bin/env python3
"""
Heapdump Secret Analyzer
Advanced analysis tool for Java heapdump files
"""

import sys
import re
import os
from collections import Counter
import argparse

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class HeapdumpAnalyzer:
    def __init__(self, heapdump_path):
        self.heapdump_path = heapdump_path
        self.secrets = {
            'passwords': [],
            'tokens': [],
            'api_keys': [],
            'jwt': [],
            'aws_keys': [],
            'database': [],
            'emails': [],
            'ips': []
        }
        
    def analyze(self):
        """Main analysis function"""
        print(f"{Colors.CYAN}[*]{Colors.ENDC} Analyzing: {self.heapdump_path}")
        
        file_size = os.path.getsize(self.heapdump_path) / (1024 * 1024)
        print(f"{Colors.CYAN}[*]{Colors.ENDC} File size: {file_size:.2f} MB")
        
        with open(self.heapdump_path, 'rb') as f:
            content = f.read()
            text = content.decode('latin-1', errors='ignore')
        
        print(f"{Colors.CYAN}[*]{Colors.ENDC} Running pattern matching...")
        
        # Find passwords
        self.find_passwords(text)
        
        # Find API keys
        self.find_api_keys(text)
        
        # Find JWT tokens
        self.find_jwt_tokens(text)
        
        # Find AWS credentials
        self.find_aws_credentials(text)
        
        # Find database credentials
        self.find_database_credentials(text)
        
        # Find email addresses
        self.find_emails(text)
        
        # Find IP addresses
        self.find_ips(text)
        
        # Print results
        self.print_results()
        
    def find_passwords(self, text):
        """Find password patterns"""
        patterns = [
            r'password["\s:=]+([^\s"\'<>]{8,})',
            r'pwd["\s:=]+([^\s"\'<>]{8,})',
            r'pass["\s:=]+([^\s"\'<>]{8,})',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                password = match.group(1)
                if self.is_valid_secret(password):
                    self.secrets['passwords'].append(password)
    
    def find_api_keys(self, text):
        """Find API key patterns"""
        patterns = [
            r'api[_-]?key["\s:=]+([a-zA-Z0-9_\-]{20,})',
            r'apikey["\s:=]+([a-zA-Z0-9_\-]{20,})',
            r'api[_-]?secret["\s:=]+([a-zA-Z0-9_\-]{20,})',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                key = match.group(1)
                if self.is_valid_secret(key):
                    self.secrets['api_keys'].append(key)
    
    def find_jwt_tokens(self, text):
        """Find JWT tokens"""
        pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        matches = re.finditer(pattern, text)
        for match in matches:
            token = match.group(0)
            self.secrets['jwt'].append(token)
    
    def find_aws_credentials(self, text):
        """Find AWS credentials"""
        # AWS Access Key ID
        aws_key_pattern = r'AKIA[0-9A-Z]{16}'
        matches = re.finditer(aws_key_pattern, text)
        for match in matches:
            self.secrets['aws_keys'].append(('Access Key', match.group(0)))
        
        # AWS Secret Key
        aws_secret_pattern = r'aws[_-]?secret["\s:=]+([a-zA-Z0-9/+=]{40})'
        matches = re.finditer(aws_secret_pattern, text, re.IGNORECASE)
        for match in matches:
            self.secrets['aws_keys'].append(('Secret Key', match.group(1)))
    
    def find_database_credentials(self, text):
        """Find database connection strings"""
        patterns = [
            r'jdbc:(?:mysql|postgresql|oracle|sqlserver)://([^\s"\'<>]+)',
            r'mongodb://([^\s"\'<>]+)',
            r'redis://([^\s"\'<>]+)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                self.secrets['database'].append(match.group(0))
    
    def find_emails(self, text):
        """Find email addresses"""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        matches = re.finditer(pattern, text)
        for match in matches:
            email = match.group(0)
            if not email.endswith('.class') and not email.endswith('.java'):
                self.secrets['emails'].append(email)
    
    def find_ips(self, text):
        """Find IP addresses"""
        pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.finditer(pattern, text)
        for match in matches:
            ip = match.group(0)
            # Filter out invalid IPs
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                self.secrets['ips'].append(ip)
    
    def is_valid_secret(self, secret):
        """Check if secret looks valid"""
        # Filter out common false positives
        blacklist = [
            'password', 'username', 'apikey', 'secret', 'token',
            'localhost', '127.0.0.1', 'example.com',
            'null', 'undefined', 'true', 'false'
        ]
        
        secret_lower = secret.lower()
        return not any(black in secret_lower for black in blacklist)
    
    def print_results(self):
        """Print analysis results"""
        print(f"\n{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}[ANALYSIS RESULTS]{Colors.ENDC}\n")
        
        total_findings = sum(len(v) for v in self.secrets.values())
        
        if total_findings == 0:
            print(f"{Colors.YELLOW}[!]{Colors.ENDC} No secrets found")
            return
        
        print(f"{Colors.GREEN}[+]{Colors.ENDC} Total findings: {total_findings}\n")
        
        # Passwords
        if self.secrets['passwords']:
            print(f"{Colors.RED}[PASSWORDS] {len(self.secrets['passwords'])} found:{Colors.ENDC}")
            unique_passwords = list(set(self.secrets['passwords']))[:10]
            for pwd in unique_passwords:
                print(f"  → {pwd}")
            if len(self.secrets['passwords']) > 10:
                print(f"  ... and {len(self.secrets['passwords']) - 10} more")
            print()
        
        # API Keys
        if self.secrets['api_keys']:
            print(f"{Colors.RED}[API KEYS] {len(self.secrets['api_keys'])} found:{Colors.ENDC}")
            unique_keys = list(set(self.secrets['api_keys']))[:10]
            for key in unique_keys:
                print(f"  → {key[:20]}...")
            if len(self.secrets['api_keys']) > 10:
                print(f"  ... and {len(self.secrets['api_keys']) - 10} more")
            print()
        
        # JWT Tokens
        if self.secrets['jwt']:
            print(f"{Colors.RED}[JWT TOKENS] {len(self.secrets['jwt'])} found:{Colors.ENDC}")
            unique_jwt = list(set(self.secrets['jwt']))[:5]
            for token in unique_jwt:
                print(f"  → {token[:50]}...")
            if len(self.secrets['jwt']) > 5:
                print(f"  ... and {len(self.secrets['jwt']) - 5} more")
            print()
        
        # AWS Credentials
        if self.secrets['aws_keys']:
            print(f"{Colors.RED}[AWS CREDENTIALS] {len(self.secrets['aws_keys'])} found:{Colors.ENDC}")
            for key_type, key in self.secrets['aws_keys'][:5]:
                print(f"  → {key_type}: {key[:30]}...")
            if len(self.secrets['aws_keys']) > 5:
                print(f"  ... and {len(self.secrets['aws_keys']) - 5} more")
            print()
        
        # Database
        if self.secrets['database']:
            print(f"{Colors.YELLOW}[DATABASE] {len(self.secrets['database'])} connections found:{Colors.ENDC}")
            unique_db = list(set(self.secrets['database']))[:5]
            for db in unique_db:
                print(f"  → {db}")
            if len(self.secrets['database']) > 5:
                print(f"  ... and {len(self.secrets['database']) - 5} more")
            print()
        
        # Emails
        if self.secrets['emails']:
            print(f"{Colors.CYAN}[EMAILS] {len(self.secrets['emails'])} addresses found:{Colors.ENDC}")
            email_counter = Counter(self.secrets['emails'])
            for email, count in email_counter.most_common(10):
                print(f"  → {email} (appeared {count}x)")
            if len(self.secrets['emails']) > 10:
                print(f"  ... and {len(self.secrets['emails']) - 10} more")
            print()
        
        # IPs
        if self.secrets['ips']:
            print(f"{Colors.CYAN}[IP ADDRESSES] {len(self.secrets['ips'])} found:{Colors.ENDC}")
            ip_counter = Counter(self.secrets['ips'])
            for ip, count in ip_counter.most_common(10):
                print(f"  → {ip} (appeared {count}x)")
            if len(self.secrets['ips']) > 10:
                print(f"  ... and {len(self.secrets['ips']) - 10} more")
            print()
        
        print(f"{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
        
        # Save to file
        self.save_results()
    
    def save_results(self):
        """Save results to file"""
        output_file = f"{self.heapdump_path}.analysis.txt"
        
        with open(output_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("HEAPDUMP ANALYSIS RESULTS\n")
            f.write("=" * 70 + "\n\n")
            
            for category, findings in self.secrets.items():
                if findings:
                    f.write(f"\n[{category.upper()}] - {len(findings)} found:\n")
                    f.write("-" * 50 + "\n")
                    for finding in set(findings):
                        if isinstance(finding, tuple):
                            f.write(f"{finding[0]}: {finding[1]}\n")
                        else:
                            f.write(f"{finding}\n")
        
        print(f"{Colors.GREEN}[+]{Colors.ENDC} Results saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Heapdump Secret Analyzer")
    parser.add_argument('heapdump', help='Path to heapdump file')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.heapdump):
        print(f"{Colors.RED}[-]{Colors.ENDC} File not found: {args.heapdump}")
        sys.exit(1)
    
    analyzer = HeapdumpAnalyzer(args.heapdump)
    analyzer.analyze()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.ENDC} Analysis interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[-]{Colors.ENDC} Error: {e}")
        sys.exit(1)
