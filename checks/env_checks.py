import re


SECRET_PATTERNS = [r"password", r"secret", r"apikey", r"token"]




def check_env_file(path, text):
findings = []
if not path.name.endswith('.env'):
return findings


for i, line in enumerate(text.splitlines(), 1):
for pattern in SECRET_PATTERNS:
if re.search(pattern, line, re.IGNORECASE):
if "=" in line:
key, val = line.split("=", 1)
if val.strip():
findings.append({
"file": str(path), "line": i,
"code": "ENV_CONTAINS_PLAIN_SECRET", "severity": "Critical",
"short": "Plaintext secret in .env file",
"detail": f"The variable `{key}` appears to contain a secret.",
"remediation": "Move secrets to a secret manager and remove them from version control."
})
return findings
