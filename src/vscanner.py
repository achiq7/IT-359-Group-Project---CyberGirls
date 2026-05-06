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
