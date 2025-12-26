#!/usr/bin/env python3
import os
import socket
import time
import statistics
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


HOST = os.getenv("HOST", "tls_like_server_patched")
PORT = int(os.getenv("PORT", "1338"))
PUB_KEY_PATH = os.getenv("PUB_KEY_PATH", "poc/Bleichenbacher/public_patched.pem")

# How many requests per mode
N_VALID = int(os.getenv("N_VALID", "200"))
N_INVALID = int(os.getenv("N_INVALID", "200"))

# For RSA-1024 => modulus length 128 bytes.
# We'll infer k from the public key so it works for other sizes too.
def load_pubkey():
    with open(PUB_KEY_PATH, "rb") as f:
        return RSA.import_key(f.read())

def send_once(payload: bytes) -> tuple[bytes, float]:
    t0 = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((HOST, PORT))
        s.sendall(payload)
        resp = s.recv(1024)
    t1 = time.perf_counter()
    return resp, (t1 - t0)

def summarize(name: str, rtts: list[float], oks: int, total: int):
    rtt_ms = [x * 1000 for x in rtts]
    print(f"\n== {name} ==")
    print(f"OK replies: {oks}/{total}")
    if rtts:
        print(f"RTT ms: mean={statistics.mean(rtt_ms):.3f}, "
              f"median={statistics.median(rtt_ms):.3f}, "
              f"p95={statistics.quantiles(rtt_ms, n=20)[18]:.3f}, "
              f"min={min(rtt_ms):.3f}, max={max(rtt_ms):.3f}")

def main():
    pub = load_pubkey()
    k = (pub.n.bit_length() + 7) // 8
    oaep = PKCS1_OAEP.new(pub, hashAlgo=SHA256)

    print(f"[+] Target = {HOST}:{PORT}")
    print(f"[+] Public key = {PUB_KEY_PATH}")
    print(f"[+] Modulus length k = {k} bytes")
    print(f"[+] Sending {N_VALID} valid OAEP ciphertexts and {N_INVALID} invalid blobs...")

    # --- Valid OAEP ciphertexts ---
    valid_rtts = []
    valid_ok = 0
    for _ in range(N_VALID):
        pt = get_random_bytes(32)  # any short plaintext fits OAEP
        ct = oaep.encrypt(pt)      # length == k
        resp, rtt = send_once(ct)
        valid_rtts.append(rtt)
        if resp == b"OK":
            valid_ok += 1

    # --- Invalid ciphertexts (random bytes of correct length) ---
    invalid_rtts = []
    invalid_ok = 0
    for _ in range(N_INVALID):
        blob = get_random_bytes(k)  # same length as RSA ciphertext, but not OAEP-valid
        resp, rtt = send_once(blob)
        invalid_rtts.append(rtt)
        if resp == b"OK":
            invalid_ok += 1

    summarize("VALID OAEP", valid_rtts, valid_ok, N_VALID)
    summarize("INVALID RANDOM", invalid_rtts, invalid_ok, N_INVALID)

    # Key claim for report:
    print("\n[Claim] If both VALID and INVALID get identical reply bytes (OK) "
          "and RTT distributions overlap closely, the oracle is mitigated.")

if __name__ == "__main__":
    main()
