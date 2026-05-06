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

