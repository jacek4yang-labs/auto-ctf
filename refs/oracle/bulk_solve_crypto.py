"""Generic bulk solver for BUUCTF CRYPTO challenges via the ctf-forge toolkit.

Walks challenges/ctf2/buuctf/CRYPTO/*/, extracts numeric parameters from the
attachment files (RSA key=value / key:value / python literals / hex), runs the
ctf-forge `crypto_rsa --attack auto` decision tree, and records results to
solve/result.json. Flags are redacted on persistence.
"""

import glob
import json
import os
import re
import subprocess
import sys

CLI = "./target/release/ctf-forge.exe"
TMP = ".tmp/bulk-params.txt"
KEY_ALIASES = {"n": "n", "N": "n", "e": "e", "c": "c", "C": "c",
               "p": "p", "q": "q", "dp": "dp", "dq": "dq", "d": "d"}


def extract_params(text):
    """Best-effort numeric parameter extraction from mixed file formats."""
    params = {}
    for line in text.splitlines():
        line = line.strip().strip(",").strip("'").strip('"')
        m = re.match(r"^\(?'?([A-Za-z_]*)\s*[:=]\s*['\"]?(0x[0-9a-fA-F]+|\d+)\)?,?$", line)
        if not m:
            continue
        key_raw, val = m.group(1), m.group(2)
        key = KEY_ALIASES.get(key_raw, KEY_ALIASES.get(key_raw.lower()))
        if key and key not in params:
            params[key] = val
    return params


def run_auto(params):
    lines = [f"{k}={v}" for k, v in params.items()]
    with open(TMP, "w") as f:
        f.write("\n".join(lines) + "\n")
    try:
        p = subprocess.run([CLI, "crypto_rsa", "--attack", "auto", "--params", TMP],
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if p.returncode != 0:
        return None, p.stderr.strip()[:200]
    return json.loads(p.stdout), None


def redact(obj):
    if isinstance(obj, str):
        return re.sub(r"(?i)(flag|dasctf|ctf)\{[^}]*\}", r"\1{FLAG_REDACTED}", obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def main(limit):
    roots = sorted(glob.glob("challenges/ctf2/buuctf/CRYPTO/*/"))
    solved = failed = skipped = 0
    for root in roots:
        name = os.path.basename(root.rstrip("/\\"))
        out_path = os.path.join(root, "solve", "result.json")
        if os.path.exists(out_path):
            skipped += 1
            continue
        files = []
        for fdir in glob.glob(root + "files/*"):
            try:
                files.append(open(fdir, encoding="utf-8", errors="replace").read())
            except OSError:
                pass
        if not files:
            continue
        merged = {}
        for text in files:
            for k, v in extract_params(text).items():
                merged.setdefault(k, v)
        if not ({"n", "c", "e"} <= set(merged) or {"n", "e"} <= set(merged)):
            skipped += 1
            continue
        res, err = run_auto(merged)
        status = "solved" if res else "failed"
        out = redact({"challenge": name, "attack": "auto", "params": sorted(merged),
                      "status": status, "result": res, "error": err})
        os.makedirs(os.path.join(root, "solve"), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        if res:
            solved += 1
        else:
            failed += 1
        if solved + failed >= limit:
            break
    print(json.dumps({"solved": solved, "failed": failed, "skipped": skipped}))


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 10**9)
