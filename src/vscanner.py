""
Smart Web App Recon + Vulnerability Reporter
Beginner-friendly starter for OWASP Juice Shop

Features:
- Checks security headers
- Checks cookie flags
- Probes common paths
- Tests a few Juice Shop API endpoints
- Performs a simple reflected input test
- Generates JSON and HTML reports

Author: Your Team
"""
import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime
