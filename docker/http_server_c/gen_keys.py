#!/usr/bin/env python3
import os, json, math, sys
from pathlib import Path
from Crypto.Util import number
from Crypto.PublicKey import RSA

KEY_DIR = Path("/app/keys")
KEY_DIR.mkdir(parents=True, exist_ok=True)

KEY_BITS = int(os.getenv("KEY_BITS", "1024"))
SCALE = int(os.getenv("TARGET_D_SCALE", "4"))
MAX_TRIES = int(os.getenv("MAX_TRIES", "20000"))

def integer_nth_root(n: int, k: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 0
    bits = n.bit_length()
    lo = 1
    hi = 1 << ((bits + k - 1) // k)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo

def generate_vulnerable_rsa(bits=KEY_BITS, scale=SCALE, max_tries=MAX_TRIES):
    half = max(8, bits // 2)
    attempt = 0
    while attempt < max_tries:
        attempt += 1
        p = number.getPrime(half)
        q = number.getPrime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        n4 = integer_nth_root(n, 4)
        if n4 <= 3:
            continue

        # Start with a base d candidate then try decreasing to find a suitably small d
        d_base = max(3, n4 // scale)

        # We'll try a sequence of candidates: d_base, d_base-2, d_base-4, ...
        # and also try slightly larger bases if necessary (rare)
        found = False
        # limit number of dec attempts per p,q to avoid huge loops
        max_dec = min(d_base - 3 if d_base > 3 else 0, 10000)
        for dec in range(0, max_dec + 1, 2):
            d_candidate = d_base - dec
            if d_candidate <= 2:
                break
            if math.gcd(d_candidate, phi) != 1:
                continue
            try:
                e = pow(d_candidate, -1, phi)
            except ValueError:
                continue
            # check Wiener-friendly heuristic: d < ~ (1/3) * n^(1/4)
            if d_candidate < max(3, n4 // 3):
                # double-check sanity of e
                if 1 < e < phi:
                    # success
                    return {"n": n, "e": e, "d": d_candidate, "p": p, "q": q, "attempts": attempt}
            # else continue trying smaller d for same p,q

        # Optionally try slightly larger starting base if dec loop didn't find
        # try a few different bases (scale variations)
        for alt_scale in (scale+1, scale+2, max(1, scale-1)):
            d_base_alt = max(3, n4 // alt_scale)
            max_dec_alt = min(d_base_alt - 3 if d_base_alt > 3 else 0, 2000)
            for dec in range(0, max_dec_alt + 1, 2):
                d_candidate = d_base_alt - dec
                if d_candidate <= 2:
                    break
                if math.gcd(d_candidate, phi) != 1:
                    continue
                try:
                    e = pow(d_candidate, -1, phi)
                except ValueError:
                    continue
                if d_candidate < max(3, n4 // 3):
                    if 1 < e < phi:
                        return {"n": n, "e": e, "d": d_candidate, "p": p, "q": q, "attempts": attempt}

    # If loop ends
    raise RuntimeError(f"Failed to generate vulnerable RSA within {max_tries} attempts")

def save_keys(info):
    n = info["n"]; e = info["e"]; d = info["d"]; p = info["p"]; q = info["q"]
    print(f"[+] Success on attempt {info.get('attempts','?')}: bits={KEY_BITS}, chosen d={d}")
    key = RSA.construct((n, e, d, p, q))
    priv_pem = key.export_key()
    pub_pem = key.publickey().export_key()
    (KEY_DIR / "server_key.pem").write_bytes(priv_pem)
    (KEY_DIR / "public.pem").write_bytes(pub_pem)
    rsa_json = {"n": str(n), "e": str(e), "d": str(d), "p": str(p), "q": str(q)}
    (KEY_DIR / "rsa.json").write_text(json.dumps(rsa_json, indent=2))
    print(f"[+] Wrote keys to {KEY_DIR}")

if __name__ == "__main__":
    print("[*] Generating vulnerable RSA keypair (lab use only!)")
    info = generate_vulnerable_rsa()
    save_keys(info)
