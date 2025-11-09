#!/bin/bash
set -e
KEYDIR=/app/keys
PEM="$KEYDIR/server.pem"
if [ ! -f "$PEM" ]; then
  /app/gen_cert.sh
fi
# tạo .rnd nếu cần
[ -f /root/.rnd ] || openssl rand -out /root/.rnd 256 || true
echo "[*] Starting old openssl s_server"
OPENSSL_CONF=/tmp/openssl.cnf /usr/local/openssl-1.0.2/bin/openssl s_server \
  -accept 4433 -cert /app/keys/server.pem -key /app/keys/server.pem \
  -cipher 'AES128-SHA' -tls1_2 -msg -debug -no_ticket
