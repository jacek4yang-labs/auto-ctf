"""Policy check: no raw flags persisted under challenges/ or docs/.

Scans every .json/.md artifact for flag-shaped strings that lack the
FLAG_REDACTED marker. Run: python scripts/scan_flag_leaks.py
"""

import json
import re
import sys
from pathlib import Path

PATTERN = re.compile(r"(?i)[\w@.-]*ctf[\w@.-]*\{[^}]+\}|flag\{[^}]+\}")
ROOTS = ["challenges", "docs", "skills", "scripts"]
EXTS = {".json", ".md"}


def iter_files():
    for root in ROOTS:
        for p in Path(root).rglob("*"):
            if p.suffix.lower() in EXTS and p.is_file():
                yield p


def main() -> int:
    leaks = []
    for p in iter_files():
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in PATTERN.finditer(text):
            if "FLAG_REDACTED" in m.group(0):
                continue
            leaks.append((str(p), m.group(0)[:60]))
    if leaks:
        print(f"{len(leaks)} leaks found:")
        for path, snippet in leaks[:20]:
            print(f"  {path}: {snippet}")
        return 1
    print("no raw flag leaks in persisted artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
