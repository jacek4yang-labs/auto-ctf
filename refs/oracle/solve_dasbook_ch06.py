"""Solve DASBOOK chapter 06 (RSA/PRNG) challenges with the ctf-forge toolkit.

Each challenge file is parsed into params, matched to the right attack, and
run through the ctf-forge CLI. Results land in <challenge>/solve/result.json.
Teaching challenges are marked [无flag] (no submit flag); recovered plaintexts
are stored with flags redacted per repo policy.
"""

import json
import os
import re
import subprocess
import sys

BASE = "challenges/ctf2/dasbook"
CLI = "./target/debug/ctf-forge.exe"
TMP = ".tmp/cli-params.txt"


def parse_params(text):
    """Parse key:value / key=value integer pairs from challenge files."""
    params = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "from ", "import ", "while", "print")):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*([0-9]+)\s*,?\s*$", line)
        if m:
            k, v = m.group(1).lower(), m.group(2)
            params.setdefault(k, v)
    return params


def run_cli(args):
    p = subprocess.run([CLI] + args, capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        return None, p.stderr.strip()
    return json.loads(p.stdout), None


def solve(name, params):
    """Pick the attack per the decision tree; returns (result_json, err, attack)."""
    keys = set(params)
    # broadcast: n1..n10 / c1..c10 with an exponent (checked first)
    if any(f"c{i}" in keys for i in (3,)) and any(f"n{i}" in keys for i in (3,)):
        e = params.get("e", "3")
        ns = [params[f"n{i}"] for i in range(1, 11) if f"n{i}" in params]
        cs = [params[f"c{i}"] for i in range(1, 11) if f"c{i}" in params]
        with open(TMP, "w") as f:
            f.write(f"e={e}\nns={','.join(ns)}\ncs={','.join(cs)}\n")
        return (*run_cli(["crypto_rsa", "--attack", "hastad", "--params", TMP]), "hastad_broadcast")
    if "p" in keys and "q" in keys and "dp" in keys and "dq" in keys and "c" in keys:
        return (*run_cli(["crypto_rsa", "--attack", "dp_dq", "--params", write_params(params)]), "dpdq")
    if "p" in keys and "q" in keys and "c" in keys and params.get("e") == "2":
        return (*run_cli(["crypto_rsa", "--attack", "rabin", "--params", write_params(params)]), "rabin")
    if "p" in keys and "q" in keys and "c" in keys and "e" not in keys:
        return (*run_cli(["crypto_rsa", "--attack", "schmidt_samoa", "--params", write_params(params)]), "schmidt_samoa")
    if "dp" in keys and "e" in keys and "n" in keys and "c" in keys:
        return (*run_cli(["crypto_rsa", "--attack", "auto", "--params", write_params(params)]), "dp_leak->from_pq")
    if "n1" in keys and "n2" in keys and "c1" in keys and "e1" not in keys:
        # shared prime: gcd(n1,n2) then decrypt with n1
        import math
        p = math.gcd(int(params["n1"]), int(params["n2"]))
        q1 = int(params["n1"]) // p
        out = {
            "shared_prime_p": str(p),
            "verified": p * q1 == int(params["n1"]),
        }
        return out, None, "shared_prime"
    if "e1" in keys and "e2" in keys and "c1" in keys and "c2" in keys and "n" in keys:
        # NOTE: must precede the n-only p-1 branch
        return (*run_cli(["crypto_rsa", "--attack", "common_modulus", "--params", write_params(params)]), "common_modulus")
    if "n" in keys and "e" in keys and "c" in keys:
        return (*run_cli(["crypto_rsa", "--attack", "auto", "--params", write_params(params)]), "auto")
    if "n" in keys and "c" not in keys and "e" not in keys:
        # bare modulus -> p-1 smooth factor attempt (high bound)
        return (*run_cli(["crypto_rsa", "--attack", "p1", "--params", write_params(params)]), "pollard_p1")
    return None, None, "unknown"


def write_params(params):
    usable = {k: v for k, v in params.items() if re.fullmatch(r"[0-9]+", v)}
    with open(TMP, "w") as f:
        for k, v in usable.items():
            f.write(f"{k}={v}\n")
    return TMP


def solve_special(cdir, challenge):
    """Two teaching challenges needing custom handling beyond the RSA tree."""
    import hashlib
    fdir = os.path.join(cdir, "files")
    files = sorted(os.listdir(fdir))
    text = open(os.path.join(fdir, files[0]), encoding="utf-8", errors="replace").read()

    if "伪随机数" in challenge and "getrandbits" in text:
        # file prints hex(random.getrandbits(32*624)); predict the next word
        m = re.search(r"#output:\s*0x([0-9a-fA-F]+)", text)
        if not m:
            return {"status": "no_hex_output"}
        bits = int(m.group(1), 16)
        outputs = [(bits >> (32 * i)) & 0xFFFFFFFF for i in range(624)]
        with open(TMP, "w") as f:
            f.write("outputs=" + ",".join(map(str, outputs)) + "\n")
        res, err = run_cli(["prng", "--kind", "mt19937", "--params", TMP])
        if err:
            return {"status": "error", "error": err[:200]}
        nxt = res["next3"][0]
        return {"status": "solved", "attack": "mt19937_predict",
                "next_word": nxt,
                "md5_candidates": [hashlib.md5(str(nxt).encode()).hexdigest(),
                                    hashlib.md5(hex(nxt).encode()).hexdigest(),
                                    hashlib.md5(str(nxt).encode()).hexdigest()]}

    if "happy" in challenge and "p^3" in text:
        # q + q*p^3 = A ; q*p + q*p^2 = B  ->  B*p^2 - (A+B)*p + B = 0
        from math import isqrt
        A = int(re.search(r"#q \+ q\*p\^3 =\s*(\d+)", text).group(1))
        B = int(re.search(r"#qp \+ q \*p\^2 =\s*(\d+)", text).group(1))
        c = int(re.search(r"c=', '0x([0-9a-fA-F]+)", text).group(1), 16)
        e = int(re.search(r"e=', '0x([0-9a-fA-F]+)", text).group(1), 16)
        disc = (A + B) ** 2 - 4 * B * B
        r = isqrt(disc)
        if r * r != disc:
            return {"status": "error", "error": "discriminant not a perfect square"}
        p_ = (A + B + r) // (2 * B)
        q_ = B // (p_ * p_ + p_)
        if p_ * q_ == 0 or B != q_ * (p_ * p_ + p_):
            return {"status": "error", "error": "algebra verification failed"}
        n_ = p_ * q_
        phi = (p_ - 1) * (q_ - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n_)
        mb = m.to_bytes((m.bit_length() + 7) // 8, "big")
        return {"status": "solved", "attack": "algebraic_p_recovery",
                "p": str(p_), "q": str(q_), "m_bytes": mb.decode(errors="replace")}

    return None


def redact(obj):
    """Recursively replace flag-shaped strings with FLAG_REDACTED (repo policy)."""
    if isinstance(obj, str):
        return re.sub(r"(?i)(flag|dasctf|ctf)\{[^}]*\}", r"{FLAG_REDACTED}", obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def main():
    summary = []
    for chapter in sorted(os.listdir(BASE)):
        chapter_dir = os.path.join(BASE, chapter)
        if not os.path.isdir(chapter_dir) or not chapter.startswith("第06章"):
            continue
        for challenge in sorted(os.listdir(chapter_dir)):
            cdir = os.path.join(chapter_dir, challenge)
            fdir = os.path.join(cdir, "files")
            if not os.path.isdir(fdir):
                continue
            files = sorted(os.listdir(fdir))
            if not files:
                continue
            text = open(os.path.join(fdir, files[0]), encoding="utf-8", errors="replace").read()
            special = solve_special(cdir, challenge)
            if special is not None:
                out = redact({"challenge": challenge, **special})
                with open(os.path.join(cdir, "solve", "result.json"), "w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, indent=1)
                summary.append({"challenge": f"{chapter}/{challenge}",
                                "attack": out.get("attack", out["status"]),
                                "status": out["status"],
                                "note": json.dumps(out, ensure_ascii=False)[:160]})
                continue
            params = parse_params(text)
            res, err, attack = solve(challenge, params)
            os.makedirs(os.path.join(cdir, "solve"), exist_ok=True)
            out = {"challenge": challenge, "attack": attack, "params_found": sorted(params)}
            if err:
                out["status"] = "error"
                out["error"] = err[:300]
            elif res:
                out["status"] = "solved"
                out["result"] = redact(res)
            else:
                out["status"] = "no_attack"
            with open(os.path.join(cdir, "solve", "result.json"), "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
            note = err[:120] if err else json.dumps(res, ensure_ascii=False)[:160]
            summary.append({"challenge": f"{chapter}/{challenge}", "attack": attack,
                            "status": out["status"], "note": note})
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    sys.exit(main())
