#!/usr/bin/env python3
import os
import socket
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes

# Env / paths
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "1337"))
# Public key will be written to this (mounted) dir so attacker can read it
PUB_DIR = os.getenv("PUB_DIR", "/app/poc/Bleichenbacher")
# Private key stays inside container in this path (NOT mounted)
PRIVATE_DIR = os.getenv("PRIVATE_DIR", "/app/keys")

# create dirs
Path(PUB_DIR).mkdir(parents=True, exist_ok=True)
Path(PRIVATE_DIR).mkdir(parents=True, exist_ok=True)

# key filenames
priv_path = os.path.join(PRIVATE_DIR, "private.pem")
pub_path = os.path.join(PUB_DIR, "public.pem")

# If keys already exist (private inside container), keep private and (re)export public
if os.path.exists(priv_path):
    # load existing private
    key = RSA.import_key(open(priv_path, "rb").read())
    # always (re)write public.pem to PUB_DIR so other containers/host see it
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    print(f"Loaded existing private key; public key exported to {pub_path}")
else:
    # generate new RSA keypair (PoC lab use)
    key = RSA.generate(1024)
    priv_pem = key.export_key()
    pub_pem = key.publickey().export_key()

    # write private *only inside container* with restrictive perms
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass

    # write public to mounted PUB_DIR so attacker can read
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    print(f"Generated new keypair. private -> {priv_path} (container-only); public -> {pub_path}")

# Prepare cipher using private key (private key kept inside container)
priv_key = RSA.import_key(open(priv_path, "rb").read())
cipher = PKCS1_v1_5.new(priv_key)
dummy_sentinel = get_random_bytes(16)

# Socket oracle (simple PKCS#1 v1.5 padding check)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server Oracle listening on {HOST}:{PORT} ...")
    while True:
        conn, addr = s.accept()
        with conn:
            # print(f"Connection from {addr}")
            try:
                data = conn.recv(65536)
                if not data:
                    continue
                result = cipher.decrypt(data, dummy_sentinel)
                if result == dummy_sentinel:
                    conn.sendall(b'FAIL')
                    print("Fail")
                else:
                    conn.sendall(b'OK')
                    print("OK")
            except Exception as e:
                try:
                    conn.sendall(b'FAIL')
                    print("Fail")
                except Exception:
                    pass
                print(f"Error handling {addr}: {e}")
