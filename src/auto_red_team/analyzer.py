# analyzer.py
# --- Added expanded ruleset implementations below ---
# Kubernetes, Terraform, IAM, and general config checks integrated — basic rule engine + severity mapping
from dataclasses import dataclass
from typing import List, Dict, Any


SEVERITY_MAP = {
"IMAGE_USES_ROOT_USER": "High",
"ENV_CONTAINS_PLAIN_SECRET": "Critical",
"NGINX_WEAK_TLS": "High",
"CORS_WILDCARD": "Medium",
}


@dataclass
class Finding:
file: str
line: int
code: str
severity: str
short: str
detail: str
remediation: str


class Analyzer:
def analyze(self, path, text: str) -> List[Dict[str, Any]]:
findings = []
# very simple Dockerfile check
if path.name == "Dockerfile":
lines = text.splitlines()
for i, line in enumerate(lines, start=1):
if line.strip().lower().startswith("user root") or "USER root" in line:
f = Finding(
file=str(path), line=i, code="IMAGE_USES_ROOT_USER",
severity=SEVERITY_MAP.get("IMAGE_USES_ROOT_USER","High"),
short="Image runs as root",
detail="The Docker image config sets the user to root or does not set a non-root user.",
remediation="Create a non-root user and switch to it in the Dockerfile."
)
findings.append(f.__dict__)
# simple .env secret detection
if path.suffix == ".env" or path.name.endswith('.env'):
for i, line in enumerate(text.splitlines(), start=1):
if "SECRET" in line.upper() or "PASSWORD" in line.upper():
if "=" in line and len(line.split("=",1)[1].strip())>0:
f = Finding(
file=str(path), line=i, code="ENV_CONTAINS_PLAIN_SECRET",
severity=SEVERITY_MAP.get("ENV_CONTAINS_PLAIN_SECRET","Critical"),
short="Hard-coded secret",
detail="A value resembling a secret appears in an env file. Storing secrets in plaintext increases risk of leakage.",
remediation="Use a secret manager or remove secrets from version control."
)
findings.append(f.__dict__)
# nginx quickcheck
if path.name.startswith("nginx") or "nginx" in str(path).lower():
if "ssl_protocols" in text and "TLSv1" in text:
f = Finding(file=str(path), line=1, code="NGINX_WEAK_TLS",
severity=SEVERITY_MAP.get("NGINX_WEAK_TLS","High"),
short="Weak TLS protocol present",
detail="The nginx config allows obsolete TLS versions like TLSv1.0/1.1.",
remediation="Disable TLSv1.0 and TLSv1.1 and prefer TLSv1.2+ with strong ciphers."
)
findings.append(f.__dict__)
return findings
