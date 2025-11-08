#!/bin/bash
set -euo pipefail

CERT_KEY="server.pem"
KEY_SIZE=1024

# Locations to try (ordered)
CANDIDATES=(
  "/usr/local/bin/openssl"
  "/usr/local/ssl/bin/openssl"
  "/usr/bin/openssl"
  "/bin/openssl"
)

OPENSSL_BIN=""

for p in "${CANDIDATES[@]}"; do
  if [ -x "$p" ]; then
    OPENSSL_BIN="$p"
    break
  fi
done

if [ -z "$OPENSSL_BIN" ]; then
  which_path=$(which openssl 2>/dev/null || true)
  if [ -n "$which_path" ] && [ -x "$which_path" ]; then
    OPENSSL_BIN="$which_path"
  fi
fi

if [ -z "$OPENSSL_BIN" ] && [ -x "/usr/local/ssl/bin/openssl" ]; then
  OPENSSL_BIN="/usr/local/ssl/bin/openssl"
fi

if [ -z "$OPENSSL_BIN" ]; then
  echo "[!] ERROR: cannot find openssl binary. Checked common locations and 'which'."
  echo "    Install openssl or adjust OPENSSL_BIN in this script."
  exit 1
fi

echo "[*] Using openssl binary: $OPENSSL_BIN"

if [ ! -f "$CERT_KEY" ]; then
  echo "[*] Generating self-signed certificate (key size: $KEY_SIZE)..."
  "$OPENSSL_BIN" req -x509 -nodes -days 365 \
    -newkey rsa:"$KEY_SIZE" \
    -keyout "$CERT_KEY" -out "$CERT_KEY" \
    -subj "/CN=tls_server"
else
  echo "[*] Using existing certificate: $CERT_KEY"
fi

echo "Starting OpenSSL TLS server on port 4433..."
CIPHER_NAME="AES128-SHA"
echo "Cipher: $CIPHER_NAME"

exec "$OPENSSL_BIN" s_server \
  -accept 4433 \
  -cert "$CERT_KEY" \
  -key "$CERT_KEY" \
  -cipher "$CIPHER_NAME" \
  -tls1_2 \
  -www \
  -msg
