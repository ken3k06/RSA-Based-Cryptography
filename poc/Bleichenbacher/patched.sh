#!/bin/bash
set -e
echo 'attack: waiting for /app/poc/Bleichenbacher/public_patched.pem ...';
until [ -f /app/poc/Bleichenbacher/public_patched.pem ]; do
  # also fallback to port check if needed
  nc -z tls_like_server 1337 && break || sleep 0.5;
done;
echo 'Key found or port open; starting attackA';
python /app/poc/Bleichenbacher/patched.py