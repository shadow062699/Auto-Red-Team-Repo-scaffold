def check_dockerfile(path, text):
findings = []
if path.name != "Dockerfile":
return findings


for i, line in enumerate(text.splitlines(), 1):
lower = line.lower()


if "user root" in lower:
findings.append({
"file": str(path), "line": i,
"code": "IMAGE_USES_ROOT_USER", "severity": "High",
"short": "Docker image uses root user",
"detail": "Running containers as root increases risk if compromised.",
"remediation": "Create and switch to a non-root user: `USER appuser`."
})


if "from" in lower and ":latest" in lower:
findings.append({
"file": str(path), "line": i,
"code": "DOCKER_UNPINNED_IMAGE", "severity": "Medium",
"short": "Unpinned Docker base image",
"detail": "Using :latest makes builds non-deterministic.",
"remediation": "Pin to a specific version or digest."
})


return findings
