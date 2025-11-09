#!/bin/bash
set -e

KEYDIR=/app/keys
mkdir -p "$KEYDIR"

# Tạo RSA 512-bit private key + self-signed cert
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:512 -out "$KEYDIR/server.key"
openssl req -new -x509 -key "$KEYDIR/server.key" -out "$KEYDIR/server.crt" -days 365 -subj "/CN=tls_server"
cat "$KEYDIR/server.crt" "$KEYDIR/server.key" > "$KEYDIR/server.pem"

echo "[*] Generated $KEYDIR/server.pem (RSA 512-bit)"
ls -l "$KEYDIR/server.pem"
