def check_terraform(path, text):
findings = []
if not path.suffix == ".tf":
return findings


for i, line in enumerate(text.splitlines(), 1):
if "0.0.0.0/0" in line:
findings.append({
"file": str(path), "line": i,
"code": "TF_OPEN_CIDR_INGRESS", "severity": "High",
"short": "Terraform ingress open to world",
"detail": "CIDR 0.0.0.0/0 allows unrestricted access.",
"remediation": "Restrict access to known IPs."
})


return findings
