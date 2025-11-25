import yaml


def check_k8s(path, text):
findings = []
if not (path.suffix in [".yml", ".yaml"] and "kind:" in text):
return findings


try:
doc = yaml.safe_load(text)
except Exception:
return findings


# Privileged containers
spec = doc.get("spec", {})
tpl = spec.get("template", {}).get("spec", {})
containers = tpl.get("containers", [])


for c in containers:
sc = c.get("securityContext", {})
if sc.get("privileged") is True:
findings.append({
"file": str(path), "line": 1,
"code": "K8S_PRIVILEGED_CONTAINER", "severity": "Critical",
"short": "Privileged Kubernetes container",
"detail": "Privileged mode gives containers host-like rights.",
"remediation": "Remove privileged: true from securityContext."
})


if sc.get("runAsUser") == 0:
findings.append({
"file": str(path), "line": 1,
"code": "K8S_CONTAINER_RUNS_AS_ROOT", "severity": "High",
"short": "Container runs as root",
"detail": "Containers should not run as UID 0.",
"remediation": "Set runAsUser to a non-zero UID."
})


return findings
