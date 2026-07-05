# Multi-Threaded-Crawler-SQLi-Scanner
# Advanced Web Radar: Multi-Threaded Crawler & SQLi Scanner

A high-performance, automated cybersecurity tool built in Python designed to crawl an entire web application domain, map internal pathways, and audit both forms and dynamic URL query strings for SQL Injection (SQLi) vulnerabilities. 

Developed with a dual-detection engine, it seamlessly uncovers hidden or silent vulnerabilities that traditional error-based scanners miss.

---

## 🚀 Key Features

*   **Recursive Web Crawling:** Automatically maps the logical infrastructure of a target domain by recursively scanning HTML source blocks for internal pathways while omitting duplicate nodes and static binary assets.
*   **Dual-Vector Vulnerability Auditing:** Tests both explicit client-side HTML `<form>` submission blocks and hidden URL query parameters (`?key=value`).
*   **Dual-Detection Engine:**
    *   **Error-Based Detection:** Maps server runtime outputs against a rich local array of known database syntax signatures (MySQL, PostgreSQL, Oracle, MSSQL).
    *   **Boolean-Based Content Anomaly Detection:** Dynamically calculates page length metrics. If an injected payload triggers changes or breaks backend queries silently, the engine flags it by identifying structural response anomalies.
*   **Zero External Dependencies:** Built leveraging clean standard utilities coupled with standard parsing frameworks (`BeautifulSoup4` & `Requests`).
*   **Vibrant UX Interface:** Styled with interactive ANSI escape sequences for structured terminal auditing feeds.

---

## 🛠️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/YOUR_GITHUB_USERNAME/advanced-sqli-radar.git](https://github.com/YOUR_GITHUB_USERNAME/advanced-sqli-radar.git)
   cd advanced-sqli-radar

   ==================================================
      ADVANCED WEB RADAR: CRAWLER & SQLi          
      Engineered by: Sithum                       
==================================================
Enter website base URL (e.g., [https://example.com](https://example.com)): [http://demo.testfire.net/index.jsp?content=personal_checking.htm](http://demo.testfire.net/index.jsp?content=personal_checking.htm)
Enter Session Cookie value (Optional for Labs, press Enter to skip): 

[Step 1] Mapping target infrastructure and discovering application paths...
[#] Crawling endpoint: [http://demo.testfire.net/index.jsp?content=personal_checking.htm](http://demo.testfire.net/index.jsp?content=personal_checking.htm)

[+] Map build sequence finished. Registered unique page paths:
  -> [http://demo.testfire.net/index.jsp](http://demo.testfire.net/index.jsp)

[Step 2] Launching multi-vector target audits across crawled elements...
  [~] Auditing URL Parameters on: [http://demo.testfire.net/index.jsp](http://demo.testfire.net/index.jsp)

[!] 🚨 VULNERABILITY DETECTED IN URL PARAMETER! 🚨
    -> Target Endpoint: [http://demo.testfire.net/index.jsp](http://demo.testfire.net/index.jsp)
    -> Attack Vector URL: [http://demo.testfire.net/index.jsp?content=personal_checking.htm](http://demo.testfire.net/index.jsp?content=personal_checking.htm)'
    -> Vulnerable Key: content
    -> Exploit Payload: '
    -> Detection Model: Content Length Anomaly

==================================================
[*] Scan cycle dead. Total confirmed SQLi points mapped: 21
==================================================


graph TD
    A[Input Domain URL] --> B[Recursive Web Crawler]
    B --> C[Isolate Clean Internal Pathways]
    C --> D[Audit Module Execution]
    D --> E[Form Scraper Audit]
    D --> F[URL Parameter Mutation Audit]
    E & F --> G[Response Signature Check]
    E & F --> H[Content Length Delta Check]
    G & H --> I[Vulnerability Flagged Alert]
