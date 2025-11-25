# src/auto_red_team/scanner.py
from pathlib import Path
from typing import List
import json
import argparse

from .analyzer import Analyzer

DEFAULT_PATTERNS = ["**/Dockerfile", "**/*.env", "**/nginx*.conf", "**/*.conf",
                    "**/*.yml", "**/*.yaml", "**/*.tf", "**/*.json"]

def _is_text(file_path: Path) -> bool:
    # quick heuristic to skip binaries
    try:
        raw = file_path.read_bytes()[:1024]
        if b'\x00' in raw:
            return False
    except Exception:
        return False
    return True

class Scanner:
    def __init__(self, root: Path):
        self.root = root
        self.analyzer = Analyzer()

    def candidate_files(self) -> List[Path]:
        candidates = []
        for pat in DEFAULT_PATTERNS:
            candidates.extend(self.root.glob(pat))
        # dedupe
        seen = set()
        out = []
        for p in candidates:
            if p.is_file() and str(p) not in seen:
                seen.add(str(p))
                out.append(p)
        return out

    def run(self):
        results = []
        for path in self.candidate_files():
            if not _is_text(path):
                continue
            try:
                text = path.read_text(errors="ignore")
            except Exception:
                continue
            file_results = self.analyzer.analyze(path, text)
            results.extend(file_results)
        return results

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--format", choices=["json","text"], default="json")
    p.add_argument("--output", default=None)
    args = p.parse_args()
    scanner = Scanner(Path(args.path))
    findings = scanner.run()
    out = json.dumps(findings, indent=2)
    if args.output:
        Path(args.output).write_text(out)
    else:
        print(out)
