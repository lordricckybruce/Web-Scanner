#!/usr/bin/env python3
import requests
import sys
import os
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

RESULTS_FILE = "sqli_scan_results.txt"

def load_payloads(file_path):
    if not os.path.exists(file_path):
        print(f"[Error] Payload file '{file_path}' not found.")
        sys.exit(1)
    try:
        with open(file_path, "r", encoding='utf-8', errors='replace') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f'[Error] Failed to read payload file: {e}')
        sys.exit(1)

def load_subdomains(file_path):
    if not os.path.exists(file_path):
        print(f"[Error] Subdomain file '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def send_request(method, url, params=None, data=None):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    }
    try:
        if method == "GET":
            resp = requests.get(url, params=params, headers=headers, timeout=15)
        else:
            resp = requests.post(url, data=data, headers=headers, timeout=15)
        return resp
    except Exception as e:
        print(f"[Request Error] {e}")
        return None

def is_vulnerable(response):
    if not response:
        return False
        
    errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "mysql_fetch_array()",
        "mysql_num_rows()",
        "syntax error",
        "sql syntax error",
        "pdoexception",
        "pg_query()",
        "mysql_fetch_assoc()",
        "supplied argument is not a valid mysql result resource",
    ]
    response_lower = response.text.lower()
    return any(err in response_lower for err in errors)

def log_result(text):
    with open(RESULTS_FILE, "a", encoding='utf-8') as f:
        f.write(text + "\n")

def report_vuln(method, url, param, payload, resp):
    header = "\n" + "=" * 70
    info = (
        f"\n[!] SQL Injection Vulnerability Detected!\n"
        f"[*] Method: {method}\n"
        f"[*] URL: {url}\n"
        f"[*] Parameter: {param}\n"
        f"[*] Payload used: {payload}\n"
        f"[*] Status Code: {resp.status_code}\n"
        f"[*] Severity: High\n"
        f"[*] Response length: {len(resp.text)}\n"
        f"[*] Response snippet:\n{resp.text[:500]}\n"
        f"{'=' * 70}\n"
    )
    print(info)
    log_result(header + info)

def test_parameter(url, param, payloads):
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query))

    for payload in payloads:
        # Test GET method
        params = query_params.copy()
        params[param] = payload
        resp = send_request("GET", base_url, params=params)
        if resp and is_vulnerable(resp):
            report_vuln("GET", base_url, param, payload, resp)
            return True

        # Test POST method
        data = query_params.copy()
        data[param] = payload
        resp = send_request("POST", base_url, data=data)
        if resp and is_vulnerable(resp):
            report_vuln("POST", base_url, param, payload, resp)
            return True

    print(f"[{param}] No SQL injection found.")
    return False

def build_urls(target, subdomains):
    urls = []
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    if subdomains:
        for sub in subdomains:
            parsed = urllib.parse.urlparse(target)
            scheme = parsed.scheme
            domain_url = f"{scheme}://{sub}.{parsed.netloc}{parsed.path}"
            urls.append(domain_url)
    else:
        urls.append(target)

    return urls

def main():
    print("=== Advanced SQL Injection Detection Tool ===")
    print(f"Results will be saved to '{RESULTS_FILE}'\n")

    target = input("Enter target domain or full URL (e.g., facebook.com or https://example.com/page.php?id=1): ").strip()
    if not target:
        print("[Error] Target is required.")
        sys.exit(1)

    has_subdomains = input("Do you have a subdomain list file? (y/n): ").strip().lower()
    subdomains = []
    if has_subdomains == 'y':
        sub_file = input("Enter subdomain list file path: ").strip()
        subdomains = load_subdomains(sub_file)

    payload_file = input("Enter payload file path: ").strip()
    payloads = load_payloads(payload_file)

    urls_to_test = build_urls(target, subdomains)

    # Initialize results file
    with open(RESULTS_FILE, "w", encoding='utf-8') as f:
        f.write(f"SQL Injection Scan Results - {datetime.now()}\n")
        f.write("=" * 70 + "\n\n")

    for url in urls_to_test:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            param_string = input(f"\nEnter parameters for {url} (e.g., search.php?q=1): ").strip()
            if not param_string.startswith(("http://", "https://")):
                if not param_string.startswith("/"):
                    param_string = "/" + param_string
                url = urllib.parse.urljoin(url, param_string)
            else:
                url = param_string

        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if not params:
            print(f"[Warning] No parameters found in URL {url}, skipping.")
            continue

        print(f"\n[+] Testing URL: {url}")
        print(f"[*] Found parameters: {', '.join(params.keys())}")
        print(f"[*] Testing with {len(payloads)} payloads per parameter...")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(test_parameter, url, param, payloads): param for param in params}
            for future in as_completed(futures):
                param = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[Error] Exception testing parameter {param}: {e}")

    print(f"\n[+] Scan complete. Results saved to '{RESULTS_FILE}'.")

if __name__ == "__main__":
    main()
