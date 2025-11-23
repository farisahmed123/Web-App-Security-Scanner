#!/usr/bin/env python3
"""
Simple SQL Injection Security Tester
Created by: Faris Nizamani (farisnizamani120@gmail.com)
Purpose: Educational tool to test web applications for SQL injection vulnerabilities
"""

import requests
import csv
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class SQLITester:
    def __init__(self):
        self.payloads = self.load_payloads()
        self.vulnerabilities = []
        
    def load_payloads(self):
        """Load SQL injection test payloads"""
        try:
            with open('payloads.txt', 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{Fore.GREEN}✓ Loaded {len(payloads)} test payloads\n{Style.RESET_ALL}")
            return payloads
        except:
            print(f"{Fore.YELLOW}! Using default payloads{Style.RESET_ALL}")
            return ["' OR '1'='1", "' OR 1=1--", "admin'--"]
    
    def check_vulnerability(self, response_text):
        """Check if response indicates SQL injection vulnerability"""
        error_keywords = ['sql', 'mysql', 'postgresql', 'sqlite', 'oracle', 
                         'syntax error', 'database error', 'query failed']
        
        response_lower = response_text.lower()
        for keyword in error_keywords:
            if keyword in response_lower:
                return True, keyword
        return False, None
    
    def get_fix_suggestion(self, param_name):
        """Simple fix suggestion for developers"""
        return f"""
HOW TO FIX:

1. Use Parameterized Queries:
   # Bad (Vulnerable):
   query = f"SELECT * FROM table WHERE {param_name} = '{{value}}'"
   
   # Good (Secure):
   from django.db import connection
   cursor.execute("SELECT * FROM table WHERE {param_name} = %s", [value])

2. Use Django ORM:
   Model.objects.filter({param_name}=value)

3. Validate Input:
   if not value.isalnum():
       return error("Invalid input")
"""
    
    def test_parameter(self, url, param_name, original_value):
        """Test one parameter with all payloads"""
        print(f"{Fore.CYAN}→ Testing: {param_name}{Style.RESET_ALL}")
        
        vulnerable = False
        
        for payload in self.payloads:
            # Build test URL
            test_url = url.replace(f"{param_name}={original_value}", f"{param_name}={payload}")
            
            try:
                response = requests.get(test_url, timeout=5)
                is_vuln, error_type = self.check_vulnerability(response.text)
                
                if is_vuln:
                    # Found vulnerability!
                    print(f"{Fore.RED}✗ VULNERABLE!{Style.RESET_ALL}")
                    print(f"  Payload: {payload}")
                    print(f"  Error: {error_type}\n")
                    
                    # Save details
                    self.vulnerabilities.append({
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'error_type': error_type,
                        'solution': self.get_fix_suggestion(param_name)
                    })
                    vulnerable = True
                    break
                    
            except Exception as e:
                continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}✓ Safe{Style.RESET_ALL}")
        
        return vulnerable
    
    def test_url(self, url):
        """Test all parameters in a URL"""
        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}Testing: {url}{Style.RESET_ALL}")
        print(f"{'='*60}\n")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"{Fore.YELLOW}No parameters found to test{Style.RESET_ALL}")
            return
        
        for param_name, values in params.items():
            self.test_parameter(url, param_name, values[0] if values else '')
        
        self.show_summary()
    
    def show_summary(self):
        """Show test results"""
        print(f"\n{'-'*60}")
        if self.vulnerabilities:
            print(f"{Fore.RED}⚠ Found {len(self.vulnerabilities)} vulnerability(ies){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ No vulnerabilities found{Style.RESET_ALL}")
        print(f"{'-'*60}\n")
    
    def save_report(self, filename='security_report.csv'):
        """Save results to CSV"""
        if not self.vulnerabilities:
            return
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'time', 'url', 'parameter', 'payload', 'error_type', 'solution'
            ])
            writer.writeheader()
            writer.writerows(self.vulnerabilities)
        
        print(f"{Fore.GREEN}✓ Report saved: {filename}{Style.RESET_ALL}\n")

def main():
    print(f"\n{Fore.YELLOW}⚠ Legal Warning: Only test your own applications!{Style.RESET_ALL}\n")
    
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python sqli_tester_enhanced.py <url>")
        print("  python sqli_tester_enhanced.py -f urls.txt")
        print("\nExample:")
        print("  python sqli_tester_enhanced.py http://127.0.0.1:8000/api/rides/?id=1")
        return
    
    tester = SQLITester()
    
    if sys.argv[1] == '-f' and len(sys.argv) > 2:
        # Test from file
        try:
            with open(sys.argv[2], 'r') as f:
                urls = [line.strip() for line in f 
                       if line.strip() and not line.startswith('#')]
            
            for url in urls:
                if url.startswith('http'):
                    tester.test_url(url)
        except:
            print(f"{Fore.RED}Error: Could not read file{Style.RESET_ALL}")
    else:
        # Test single URL
        tester.test_url(sys.argv[1])
    
    # Save results
    tester.save_report('ShareCare_Vulnerability_Report.csv')

if __name__ == '__main__':
    main()
