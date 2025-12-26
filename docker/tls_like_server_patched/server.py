#!/usr/bin/env python3
import os
import socket
import time
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# Env / paths
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "1338"))

PUB_DIR = os.getenv("PUB_DIR", "/app/poc/Bleichenbacher")
PRIVATE_DIR = os.getenv("PRIVATE_DIR", "/app/keys")

Path(PUB_DIR).mkdir(parents=True, exist_ok=True)
Path(PRIVATE_DIR).mkdir(parents=True, exist_ok=True)

# Separate patched keys (good for lab)
priv_path = os.path.join(PRIVATE_DIR, "private_patched.pem")
pub_path = os.path.join(PUB_DIR, "public_patched.pem")

# Load or generate keypair
if os.path.exists(priv_path):
    key = RSA.import_key(open(priv_path, "rb").read())
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    print(f"[patched-oaep] Loaded existing private key; exported public -> {pub_path}")
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
    print(f"[patched-oaep] Generated new keypair. private -> {priv_path} (container-only); public -> {pub_path}")

priv_key = RSA.import_key(open(priv_path, "rb").read())

# OAEP (modern encryption padding) - using SHA256 + MGF1(SHA256)
oaep_cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)

# --- Mitigation strategy ---
# 1) Never reveal validity: always same reply
# 2) Reduce timing differences: deterministic-ish dummy work
UNIFORM_REPLY = b"OK"


def _dummy_equalize_work(data: bytes) -> None:
    h = SHA256.new()
    # hash fixed 64 bytes (pad with zeros) to keep work constant-ish
    block = (data[:64] + b"\x00" * 64)[:64]
    h.update(block)
    _ = h.digest()
    # tiny fixed delay (optional, lab only)
    time.sleep(0.001)


def handle_client(conn: socket.socket, addr):
    try:
        data = conn.recv(65536)
        if not data:
            return

        # Attempt OAEP decrypt but DO NOT branch response on success/failure.
        # OAEP raises ValueError on invalid ciphertext; we swallow it uniformly.
        try:
            _ = oaep_cipher.decrypt(data)
        except Exception:
            pass

        _dummy_equalize_work(data)
        conn.sendall(UNIFORM_REPLY)

    except Exception:
        # Even on exception, keep uniform behavior
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
        print(f"[patched-oaep] Server listening on {HOST}:{PORT} (OAEP + uniform response)")

        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn, addr)


if __name__ == "__main__":
    main()
