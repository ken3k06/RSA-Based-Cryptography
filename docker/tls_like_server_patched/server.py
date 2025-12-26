#!/usr/bin/env python3
import os
import socket
import time
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


# Env / paths
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "1338"))

# Public key can be exported to a mounted dir (same as your PoC)
PUB_DIR = os.getenv("PUB_DIR", "/app/poc/Bleichenbacher")
PRIVATE_DIR = os.getenv("PRIVATE_DIR", "/app/keys")

Path(PUB_DIR).mkdir(parents=True, exist_ok=True)
Path(PRIVATE_DIR).mkdir(parents=True, exist_ok=True)

priv_path = os.path.join(PRIVATE_DIR, "private_patched.pem")
pub_path = os.path.join(PUB_DIR, "public_patched.pem")

# Load or generate keypair
if os.path.exists(priv_path):
    key = RSA.import_key(open(priv_path, "rb").read())
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    print(f"[patched] Loaded existing private key; exported public -> {pub_path}")
else:
    key = RSA.generate(1024)  # lab only
    with open(priv_path, "wb") as f:
        f.write(key.export_key())
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    print(f"[patched] Generated new keypair. private -> {priv_path} (container-only); public -> {pub_path}")

priv_key = RSA.import_key(open(priv_path, "rb").read())
cipher = PKCS1_v1_5.new(priv_key)

# --- Patch strategy ---
# 1) Never reveal padding validity: always same response bytes
# 2) Reduce timing differences: always do some dummy work
UNIFORM_REPLY = b"OK"  # could be any constant; important is it's ALWAYS the same


def _dummy_equalize_work(data: bytes) -> None:
    """
    Do deterministic-ish work to reduce timing signal.
    Not a perfect constant-time guarantee in Python, but helps for lab demo.
    """
    # Hash a fixed amount, include received data to avoid being optimized away
    h = SHA256.new()
    h.update(data[:64] + b"\x00" * max(0, 64 - len(data[:64])))
    _ = h.digest()

    # Add a tiny fixed sleep to blur micro-differences (optional)
    # Keep small so it doesn't slow too much.
    time.sleep(0.001)


def handle_client(conn: socket.socket, addr):
    try:
        data = conn.recv(65536)
        if not data:
            return

        # Always attempt decrypt with sentinel, but DO NOT branch response on result
        sentinel = get_random_bytes(16)
        _ = cipher.decrypt(data, sentinel)

        # Equalize workload regardless of padding validity
        _dummy_equalize_work(data)

        # Always same response
        conn.sendall(UNIFORM_REPLY)

    except Exception:
        # Even on exception, try to preserve uniform behavior
        try:
            _dummy_equalize_work(b"")
            conn.sendall(UNIFORM_REPLY)
        except Exception:
            pass


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[patched] Server listening on {HOST}:{PORT} (uniform response, mitigated oracle)")

        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn, addr)


if __name__ == "__main__":
    main()
