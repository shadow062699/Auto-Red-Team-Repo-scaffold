# --- Kubernetes Checks Implementation ---
findings.append({
"file": str(path),
"line": i,
"code": "IAM_WILDCARD_ACTION",
"severity": "Critical",
"short": "IAM policy allows all actions",
"detail": "Granting Action: * gives full permissions.",
"remediation": "Limit actions to the minimum set required."
})
if '"Resource": "*"' in line:
findings.append({
"file": str(path),
"line": i,
"code": "IAM_WILDCARD_RESOURCE",
"severity": "High",
"short": "IAM policy applies to all resources",
"detail": "Using Resource: * may expose unintended resources.",
"remediation": "Specify exact resource ARNs."
})
return findings


# --- General Config Checks ---
def _check_weak_hashes(text, path):
findings = []
for i, line in enumerate(text.splitlines(), 1):
if "md5" in line.lower() or "sha1" in line.lower():
findings.append({
"file": str(path),
"line": i,
"code": "WEAK_HASH_FUNCTION",
"severity": "Medium",
"short": "Weak cryptographic hash detected",
"detail": "MD5 and SHA1 are deprecated and vulnerable to collision attacks.",
"remediation": "Use SHA-256 or stronger algorithms."
})
return findings


# scanner.py — walk a directory and read candidate files
from pathlib import Path
from typing import List


from auto_red_team.analyzer import Analyzer


class Scanner:
def __init__(self, root: Path):
self.root = root
self.analyzer = Analyzer()


def candidate_files(self) -> List[Path]:
patterns = ["**/Dockerfile", "**/*.env", "**/nginx*.conf", "**/*.yml", "**/*.yaml", "**/*.tf"]
candidates = []
for pat in patterns:
candidates.extend(self.root.glob(pat))
return candidates


def run(self):
results = []
for path in self.candidate_files():
try:
text = path.read_text(errors="ignore")
except Exception:
continue
file_results = self.analyzer.analyze(path, text)
results.extend(file_results)
return results


# CLI entrypoint (simple)
if __name__ == "__main__":
import argparse, json
p = argparse.ArgumentParser()
p.add_argument("path", nargs="?", default=".")
args = p.parse_args()
scanner = Scanner(Path(args.path))
findings = scanner.run()
print(json.dumps(findings, indent=2))
