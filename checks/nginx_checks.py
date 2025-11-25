def check_nginx(path, text):
findings = []
if "nginx" not in str(path).lower():
return findings


if "ssl_protocols" in text and ("TLSv1 " in text or "TLSv1.1" in text):
findings.append({
"file": str(path), "line": 1,
"code": "NGINX_WEAK_TLS", "severity": "High",
"short": "Weak TLS versions enabled",
"detail": "TLSv1.0/1.1 are outdated and insecure.",
"remediation": "Use only TLSv1.2 or TLSv1.3."
})


if "add_header Access-Control-Allow-Origin *" in text:
findings.append({
"file": str(path), "line": 1,
"code": "CORS_WILDCARD_ORIGIN", "severity": "Medium",
"short": "CORS wildcard detected",
"detail": "Wildcard CORS can expose APIs to untrusted origins.",
"remediation": "Set a specific allowed domain instead of `*`."
})


return findings
