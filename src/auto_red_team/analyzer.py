# src/auto_red_team/analyzer.py
"""
Analyzer: auto-discovers check modules under auto_red_team.checks
and normalizes findings to a consistent schema:

{
  "file": "<path>",
  "line": <int>,
  "code": "<FINDING_CODE>",
  "severity": "Critical|High|Medium|Low|Info",
  "short": "<one-line summary>",
  "detail": "<longer description>",
  "remediation": "<suggested fix>"
}
"""
import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict, Any

from . import checks as checks_pkg

class Analyzer:
    def __init__(self):
        # Nothing heavy on init; checks package will be used on demand
        self._modules = self._discover_check_modules()

    def _discover_check_modules(self) -> List:
        modules = []
        package_path = Path(checks_pkg.__file__).parent
        for module_info in pkgutil.iter_modules([str(package_path)]):
            full_name = f"{checks_pkg.__package__}.{module_info.name}"
            try:
                m = importlib.import_module(full_name)
            except Exception:
                # ignore modules that fail to import (but optionally log)
                continue
            modules.append(m)
        return modules

    def analyze(self, path: Path, content: str) -> List[Dict[str, Any]]:
        """
        Run all checks for the given file content. Each check module should
        expose one or more check functions that accept (path, text) and return
        a list of finding dicts in the normalized schema (or similar).
        We'll accept small variations but normalize here.
        """
        findings: List[Dict[str, Any]] = []

        # If checks package exposes run_all_checks use it (convenience)
        if hasattr(checks_pkg, "run_all_checks"):
            raw = checks_pkg.run_all_checks(path, content)
            findings.extend(self._normalize(raw))
            return findings

        # Otherwise call discoverd modules and common function names
        for m in self._modules:
            for fname in ("check_dockerfile", "check_env_file", "check_nginx",
                          "check_k8s", "check_terraform", "check_iam", "check_all"):
                if hasattr(m, fname):
                    try:
                        raw = getattr(m, fname)(path, content)
                        findings.extend(self._normalize(raw))
                    except Exception:
                        # ignore failing checks to keep scanning resilient
                        continue
        return findings

    def _normalize(self, raw_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize variety of finding dict shapes into a canonical schema"""
        out = []
        for r in raw_list:
            # simple tolerant mapping
            item = {
                "file": r.get("file") or r.get("path") or "",
                "line": int(r.get("line") or r.get("lineno") or 0),
                "code": r.get("code") or r.get("id") or r.get("finding") or "UNKNOWN",
                "severity": r.get("severity") or r.get("level") or "Info",
                "short": r.get("short") or r.get("title") or "",
                "detail": r.get("detail") or r.get("description") or "",
                "remediation": r.get("remediation") or r.get("fix") or "",
            }
            out.append(item)
        return out
