"""

Vulnerability Scanner
OWASP Juice Shop Reconnaissance

Features:
- Checks security headers
- Checks cookie flags
- Probes common paths
- Tests a few Juice Shop API endpoints
- Performs a simple reflected input test
- Generates JSON and HTML reports

"""
import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime

#add more code
from urllib.parse import urljoin, urlparse

import requests


# -----------------------------
# Data model
# -----------------------------
@dataclass
class Finding:
    title: str
    severity: str
    url: str
    description: str
    evidence: str
    recommendation: str


# -----------------------------
# Scanner class
# -----------------------------
class WebReconScanner:
    def __init__(self, base_url: str, timeout: int = 8):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebRecon/1.0 (Educational Project)" #let website know not to worry 
        })
        self.findings = []
        self.scanned_urls = []

    def add_finding(self, title, severity, url, description, evidence, recommendation):
        self.findings.append(Finding(
            title=title,
            severity=severity,
            url=url,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        ))
    def safe_get(self, path: str, params=None):
        """
        Send a GET request to a URL:
        - if full URL, uses that
        - if a path is given, put onto the base URL
        """
        url = path if path.startswith("http") else urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            response = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            self.scanned_urls.append(response.url)
            return response
        except requests.RequestException as exc:
            self.add_finding(
                title="Request Failure",
                severity="Info",
                url=url,
                description="The scanner couldn't get a target url",
                evidence=str(exc),
                recommendation="Verify that the application is running and reachable from the host environment"
            )
            return None
    def check_homepage(self):
        response = self.safe_get("/")
        if response is None:
            return None

        if response.status_code == 200:
            print(f"[+] Homepage reachable: {response.url}")
        else:
            self.add_finding(
                title="Homepage returned unexpected status",
                severity="Low",
                url=response.url,
                description="The application homepage responded with a non-200 status code.",
                evidence=f"HTTP {response.status_code}",
                recommendation="Review routing, deployment, or reverse proxy configuration."
            )
        return response

    def check_security_headers(self, response):
        if response is None:
            return

        headers = response.headers
        url = response.url

        required_headers = {
            "Content-Security-Policy": {
                "severity": "Medium",
                "description": "Without, people can get in and run their own script- XSS",
                "recommendation": "Add content-security-policy header that allows scripts only you actually trust."
            },
            "X-Frame-Options": {
                "severity": "Low",
                "description": "Without, someone could put your site inside theirs and get people to click things",
                "recommendation": "Set x-frame-options to DENY (nobody can frame it) or SAMEORIGIN (only you can)"
            },
            "X-Content-Type-Options": {
                "severity": "Low",
                "description": "Without, site may try running the site as a different file",
                "recommendation": "Set x-content-type-options to nosniff so browser trusts what you tell it"
            },
            "Referrer-Policy": {
                "severity": "Low",
                "description": "Without, if someone clicks on your site, the next site will know where they came from (>
                "recommendation": "Set referrer-policy to strict-origin-when-cross-origin, to not overshare"
            }
        }

        for header, meta in required_headers.items():
            if header not in headers:
                self.add_finding(
                    title=f"Missing Security Header: {header}",
                    severity=meta["severity"],
                    url=url,
                    description=meta["description"],
                    evidence=f"{header} was not present in the response headers.",
                    recommendation=meta["recommendation"]
                )

        # HSTS only makes sense over HTTPS
        parsed = urlparse(url)
        if parsed.scheme == "https" and "Strict-Transport-Security" not in headers:
            self.add_finding(
                title="Missing Security Header: Strict-Transport-Security",
                severity="Medium",
                url=url,
                description="HTTPS is in use, HSTS not enabled.",
                evidence="Strict-Transport-Security header isn't present in the HTTPS response.",
                recommendation="Enable HSTS to help enforce secure connections."
            )

    def check_cookies(self, response):
        if response is None:
            return

        url = response.url
        set_cookie_headers = response.headers.get("Set-Cookie")

        if not set_cookie_headers:
            self.add_finding(
                title="No Cookies Observed",
                severity="Info",
                url=url,
                description="No cookies seen",
                evidence="Set-Cookie header not present.",
                recommendation="This may be normal. Review authenticated areas separately for session cookie security"
            )
            return

        cookie_header = set_cookie_headers.lower()

        if "httponly" not in cookie_header:
            self.add_finding(
                title="Cookie Missing HttpOnly Flag",
                severity="Medium",
                url=url,
                description="A cookie appears to be set without the HttpOnly flag (unprotected)",
                evidence=response.headers.get("Set-Cookie", ""),
                recommendation="Mark session cookies as HttpOnly so random scripts cant grab them"
            )

        if urlparse(url).scheme == "https" and "secure" not in cookie_header:
            self.add_finding(
                title="Cookie Missing Secure Flag",
                severity="Medium",
                url=url,
                description="A cookie appears to be set over HTTPS without the Secure flag, can be sent to HTTP too",
                evidence=response.headers.get("Set-Cookie", ""),
                recommendation="Add the secure flag to cookies to only travel over HTTPS"
            )
        if "samesite" not in cookie_header:
            self.add_finding(
                title="Cookie Missing SameSite Attribute",
                severity="Low",
                url=url,
                description="A cookie is  missing a SameSite, ",
                evidence=response.headers.get("Set-Cookie", ""),
                recommendation="Use SameSite=Lax (safe default) or SameSite=Strict (extra safe) on cookies"
            )

    def probe_common_paths(self):
        """
        Probe common files and a few Juice Shop-related endpoints.
        """
        paths = [
            "/robots.txt",
            "/.git/",
            "/backup",
            "/admin",
            "/ftp",
            "/api-docs",
            "/rest/admin/application-version",
            "/api/Challenges",
            "/rest/products/search?q=test"
        ]

        for path in paths:
            response = self.safe_get(path)
            if response is None:
                continue

            status = response.status_code

            if status == 200:
                self.add_finding(
                    title="Interesting Path Accessible",
                    severity="Info",
                    url=response.url,
                    description="The scanner found an accessible path that may warrant manual review.",
                    evidence=f"Accessible path returned HTTP 200: {response.url}",
                    recommendation="Manually inspect the resource to determine whether it discloses sensitive functionality or information."
                )
            elif status in (401, 403):
                self.add_finding(
                    title="Restricted Path Detected",
                    severity="Info",
                    url=response.url,
                    description="A restricted path was identified, indicating potentially sensitive functionality.",
                    evidence=f"Path returned HTTP {status}: {response.url}",
                    recommendation="Review access controls and confirm the endpoint is intended to be exposed."
                )

    def check_robots_txt(self):
        response = self.safe_get("/robots.txt")
        if response is None:
            return

        if response.status_code == 200 and response.text.strip():
            disallowed = []
            for line in response.text.splitlines():
                if line.lower().startswith("disallow:"):
                    disallowed.append(line.strip())

            if disallowed:
                self.add_finding(
                    title="robots.txt Reveals Hidden Paths",
                    severity="Low",
                    url=response.url,
                    description="robots.txt may disclose directories or routes not intended for obvious discovery.",
                    evidence=" | ".join(disallowed),
                    recommendation="Do not rely on robots.txt to hide sensitive resources. Protect sensitive endpoints with authentication and authorization."
                )

     def reflected_input_test(self):
        """
        Simple reflected input test against a search endpoint.
        This is an indicator-based check, not a full XSS exploit.
        """
        marker = "RECON_TEST_123456"
        response = self.safe_get("/rest/products/search", params={"q": marker})
        if response is None:
            return

        if marker in response.text:
            self.add_finding(
                title="Reflected Input Indicator Detected",
                severity="Medium",
                url=response.url,
                description="User-controlled input was reflected in the response.",
                evidence=f"Marker '{marker}' appeared in the response body.",
                recommendation="Review output encoding and input handling to reduce reflected XSS risk."
            )
    def error_disclosure_test(self):
        """
        Simple error-string test.
        This is not exploitation—just checking whether obvious backend error details leak.
        """
        suspicious_inputs = ["'", "\"", "')", "test)"]
        error_patterns = [
            r"sql syntax",
            r"mysql",
            r"sqlite",
            r"postgres",
            r"unclosed quotation mark",
            r"odbc",
            r"stack trace",
            r"exception"
        ]

        for payload in suspicious_inputs:
            response = self.safe_get("/rest/products/search", params={"q": payload})
            if response is None:
                continue

            text_lower = response.text.lower()
            for pattern in error_patterns:
                if re.search(pattern, text_lower):
                    self.add_finding(
                        title="Potential Error Disclosure Detected",
                        severity="Medium",
                        url=response.url,
                        description="The application response contained backend or debugging error indicators after receiving unusual input.",
                        evidence=f"Matched pattern '{pattern}' using payload '{payload}'.",
                        recommendation="Suppress detailed backend errors and implement safe exception handling."
                    )
                    return  # one finding is enough here

    def save_json_report(self, filename="results.json"):
        data = {
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "base_url": self.base_url,
            "scanned_urls": sorted(set(self.scanned_urls)),
            "findings": [asdict(f) for f in self.findings]
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        print(f"[+] JSON report saved to {filename}")

    def save_html_report(self, filename="report.html"):
        findings_html = ""
        for finding in self.findings:
            findings_html += f"""
            <div class="finding">
                <h2>{finding.title}</h2>
                <p><strong>Severity:</strong> {finding.severity}</p>
                <p><strong>URL:</strong> {finding.url}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Evidence:</strong> {finding.evidence}</p>
                <p><strong>Recommendation:</strong> {finding.recommendation}</p>
            </div>
            """

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Smart Web App Recon Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background: #f8f9fa;
                    color: #222;
                }}
                h1 {{
                    color: #1f4e79;
                }}
                .meta {{
                    margin-bottom: 20px;
                    padding: 15px;
                    background: #ffffff;
                    border-left: 5px solid #1f4e79;
                }}
                .finding {{
                    background: #ffffff;
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 8px;
                }}
                h2 {{
                    margin-top: 0;
                }}
            </style>
        </head>
        <body>
            <h1>Smart Web App Recon + Vulnerability Reporter</h1>
            <div class="meta">
                <p><strong>Base URL:</strong> {self.base_url}</p>
                <p><strong>Scan Time (UTC):</strong> {datetime.utcnow().isoformat()}Z</p>
                <p><strong>Total Findings:</strong> {len(self.findings)}</p>
            </div>
            {findings_html if findings_html else "<p>No findings were recorded.</p>"}
        </body>
        </html>
        """

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[+] HTML report saved to {filename}")

    def run(self):
        print(f"[+] Starting scan against {self.base_url}")
        homepage_response = self.check_homepage()
        self.check_security_headers(homepage_response)
        self.check_cookies(homepage_response)
        self.check_robots_txt()
        self.probe_common_paths()
        self.reflected_input_test()
        self.error_disclosure_test()
        print(f"[+] Scan complete. Findings collected: {len(self.findings)}")

# -----------------------------
# Main
# -----------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Smart Web App Recon + Vulnerability Reporter")
    parser.add_argument("--url", required=True, help="Base URL of the target web app, e.g. http://localhost:3000")
    parser.add_argument("--json", default="results.json", help="Output JSON filename")
    parser.add_argument("--html", default="report.html", help="Output HTML filename")
    return parser.parse_args()

def main():
    args = parse_args()
    scanner = WebReconScanner(args.url)
    scanner.run()
    scanner.save_json_report(args.json)
    scanner.save_html_report(args.html)


if __name__ == "__main__":
    main()
