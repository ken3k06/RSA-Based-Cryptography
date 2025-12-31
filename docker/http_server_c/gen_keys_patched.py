#!/usr/bin/env python3
import os, json, math
from pathlib import Path
from Crypto.PublicKey import RSA

KEY_DIR = Path("/app/keys")
KEY_DIR.mkdir(parents=True, exist_ok=True)

KEY_BITS = int(os.getenv("KEY_BITS", "2048"))  # khuyến nghị 2048+
E = int(os.getenv("RSA_E", "65537"))
MAX_TRIES = int(os.getenv("MAX_TRIES", "200"))

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

def wiener_threshold(n: int) -> int:
    # floor(N^(1/4)/3)
    n4 = integer_nth_root(n, 4)
    return max(3, n4 // 3)

def gen_safe_rsa(bits=KEY_BITS, e=E, max_tries=MAX_TRIES) -> RSA.RsaKey:
    for attempt in range(1, max_tries + 1):
        key = RSA.generate(bits, e=e)
        n = key.n
        d = key.d
        th = wiener_threshold(n)
        # Patch chống Wiener: d phải >= N^(1/4)/3
        if d >= th:
            print(f"[+] Generated SAFE RSA on attempt {attempt}: bits={bits}, e={e}, d_bits={d.bit_length()}")
            return key
        print(f"[-] Reject weak key (Wiener): attempt={attempt}, d_bits={d.bit_length()} < threshold~{th.bit_length()} bits")
    raise RuntimeError(f"Failed to generate SAFE RSA within {max_tries} attempts")

def save_keys(key: RSA.RsaKey):
    priv_pem = key.export_key()
    pub_pem = key.publickey().export_key()
    (KEY_DIR / "server_key_patched.pem").write_bytes(priv_pem)
    (KEY_DIR / "public_patched.pem").write_bytes(pub_pem)

    # Nếu vẫn muốn debug, KHÔNG ghi p,q,d ra file nữa.
    rsa_json = {"n": str(key.n), "e": str(key.e), "d": str(key.d), "p": str(key.p), "q": str(key.q), "d_bits": key.d.bit_length()}
    (KEY_DIR / "rsa_patch.json").write_text(json.dumps(rsa_json, indent=2))

    print(f"[+] Wrote keys to {KEY_DIR}")

if __name__ == "__main__":
    print("[*] Generating SAFE RSA keypair")
    key = gen_safe_rsa()
    save_keys(key)
