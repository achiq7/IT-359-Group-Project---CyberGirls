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

