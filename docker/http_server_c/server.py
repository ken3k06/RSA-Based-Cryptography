#!/usr/bin/env python3
from flask import Flask, send_file, jsonify, request, make_response
import os
from pathlib import Path
import subprocess
import json
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# -----------------------
# Key setup
# -----------------------
KEY_DIR = Path("/app/keys")
SERVER_KEY = KEY_DIR / "server_key.pem"
PUBLIC_PEM = KEY_DIR / "public.pem"
RSA_JSON = KEY_DIR / "rsa.json"

def ensure_keys():
    if not SERVER_KEY.exists() or not PUBLIC_PEM.exists() or not RSA_JSON.exists():
        print("[*] Keys not found. Generating new vulnerable keys...")
        subprocess.check_call(["python", "/app/gen_keys.py"])
    else:
        print("[*] Existing keys found.")

ensure_keys()

app = Flask(__name__)

# -----------------------
# Helpers
# -----------------------
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode())

def sign_jwt(payload: dict) -> str:
    """Manual RS256 signing using PyCryptodome"""
    header = {"alg": "RS256", "typ": "JWT"}
    header_b = json.dumps(header, separators=(',', ':'), sort_keys=True).encode()
    payload_b = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    signing_input = b"%s.%s" % (
        base64.urlsafe_b64encode(header_b).rstrip(b"="),
        base64.urlsafe_b64encode(payload_b).rstrip(b"="),
    )
    h = SHA256.new(signing_input)
    key = RSA.import_key(SERVER_KEY.read_text())
    sig = pkcs1_15.new(key).sign(h)
    return signing_input.decode() + "." + b64url_encode(sig)

def verify_jwt(token: str):
    """Verify RS256 signature manually and return payload or raise"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token format invalid")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    sig = b64url_decode(parts[2])
    h = SHA256.new(signing_input)
    pubkey = RSA.import_key(PUBLIC_PEM.read_text())
    pkcs1_15.new(pubkey).verify(h, sig)
    payload_json = b64url_decode(parts[1]).decode("utf-8")
    return json.loads(payload_json)

# -----------------------
# Routes
# -----------------------
@app.route("/public.pem", methods=["GET"])
def public_pem():
    return send_file(str(PUBLIC_PEM), mimetype="application/x-pem-file")

@app.route("/rsa.json", methods=["GET"])
def rsa_json():
    data = json.loads(RSA_JSON.read_text())
    return jsonify(data)

@app.route("/token", methods=["GET"])
def token_endpoint():
    sub = request.args.get("sub", "attacker")
    role = request.args.get("role", "user")
    exp_seconds = int(request.args.get("exp", "3600"))
    now = int(time.time())
    payload = {"sub": sub, "role": role, "iat": now, "exp": now + exp_seconds}
    token = sign_jwt(payload)
    return jsonify({"token": token})

@app.route("/")
def index():
    """Generate guest JWT and store it in cookie"""
    now = int(time.time())
    payload = {
        "sub": "guest",
        "role": "guest",
        "iat": now,
        "exp": now + 3600
    }
    guest_token = sign_jwt(payload)
    html = f"""
    <h3>RSA Wiener's lab HTTP server</h3>
    <p><b>Guest JWT has been set in cookie <code>auth_token</code>.</b></p>
    <textarea rows="4" cols="90" readonly>{guest_token}</textarea>
    <br><br>
    <ul>
      <li><a href="/public.pem">/public.pem</a> — public key (PEM)</li>
      <li><a href="/rsa.json">/rsa.json</a> — (lab debug) key components</li>
      <li><a href="/token">/token</a> — get a JWT signed with server key</li>
      <li><a href="/admin">/admin</a> — admin panel</li>
    </ul>
    <p><b>Note:</b> This server is for lab use only.</p>
    """
    resp = make_response(html)
    resp.set_cookie("auth_token", guest_token, httponly=False, samesite="Lax")
    return resp

@app.route("/admin", methods=["GET"])
def admin_panel():
    token = request.cookies.get("auth_token")
    if not token:
        return jsonify({"ok": False, "error": "missing cookie auth_token"}), 401
    try:
        payload = verify_jwt(token)
    except Exception as e:
        return jsonify({"ok": False, "error": f"invalid token: {e}"}), 401
    role = payload.get("role", "")
    if role != "admin":
        return jsonify({"ok": False, "error": f"access denied: role '{role}'"}), 403
    return jsonify({
        "ok": True,
        "message": "Welcome, admin!",
        "flag": "FLAG{weiner_attack_with_jwt}",
        "role": role,
        "payload": payload
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
