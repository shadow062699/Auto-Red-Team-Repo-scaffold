def check_iam(path, text):
findings = []


if not (path.suffix in [".json", ".yml", ".yaml"] and "Action" in text):
return findings


for i, line in enumerate(text.splitlines(), 1):
if '"Action": "*"' in line:
findings.append({
"file": str(path), "line": i,
"code": "IAM_WILDCARD_ACTION", "severity": "Critical",
"short": "IAM wildcard actions",
"detail": "Allows all actions across all services.",
"remediation": "Restrict the action list."
})


if '"Resource": "*"' in line:
findings.append({
"file": str(path), "line": i,
"code": "IAM_WILDCARD_RESOURCE", "severity": "High",
"short": "IAM wildcard resource",
"detail": "Policy applies to every resource.",
"remediation": "Specify exact resource ARNs."
})


return findings
```` — sample vulnerable files and sample output
- `.github/workflows/ci.yml` — basic CI lint + tests
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`


---


## Quickstart (local)


```bash
# create venv, install
python -m venv .venv
source .venv/bin/activate
pip install -e .


# run a scan (scans current directory by default)
auto-red-team scan . --format json --output findings.json
