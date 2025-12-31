#!/bin/bash
gcc docker/http_server_b/server.c -o docker/http_server_b/server -lcrypto
docker-compose up -d --build

echo "[*] Docker containers are being built and started."
