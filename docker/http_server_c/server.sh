#!/bin/bash
set -e

echo "[*] Starting server.sh..."
echo "[*] Generating vulnerable RSA keys if not exist..."

KEY_DIR="/app/keys"
mkdir -p "$KEY_DIR"

# Nếu đã có key thì bỏ qua sinh lại
if [ -f "$KEY_DIR/server_key.pem" ] && [ -f "$KEY_DIR/public.pem" ] && [ -f "$KEY_DIR/server_key_patched.pem" ] && [ -f "$KEY_DIR/public_patched.pem" ]; then
    echo "[+] Keys already exist, skipping generation."
else
    echo "[*] Running gen_keys.py..."
    python /app/gen_keys_patched.py || { echo "[!] Key generation failed."; exit 1; }
    python /app/gen_keys.py || { echo "[!] Key generation failed."; exit 1; }
fi

echo "[*] Starting Flask server..."
# Chạy Flask server (không debug, binding 0.0.0.0)
exec python /app/server.py

