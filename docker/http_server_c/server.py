#!/usr/bin/env python3
from flask import Flask, send_file, jsonify, request, make_response
import os
from pathlib import Path
import subprocess
import json
import time
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# -----------------------
# Key setup
# -----------------------
KEY_DIR = Path("/app/keys")

# Legacy (your existing vulnerable key locations) - DO NOT REMOVE
LEGACY_SERVER_KEY = KEY_DIR / "server_key.pem"
LEGACY_PUBLIC_PEM = KEY_DIR / "public.pem"
LEGACY_RSA_JSON = KEY_DIR / "rsa.json"

# New: patched key lives in subdir
PATCHED_SERVER_KEY = KEY_DIR / "server_key_patched.pem"
PATCHED_PUBLIC_PEM = KEY_DIR / "public_patched.pem"

# Keygen scripts
VULN_KEYGEN = os.getenv("VULN_KEYGEN", "/app/gen_keys.py")
PATCHED_KEYGEN = os.getenv("PATCHED_KEYGEN", "/app/gen_keys_patched.py")  # <-- đổi tên nếu bạn đặt khác

# KIDs (explicit, easy for lab/report)
VULN_KID = os.getenv("VULN_KID", "lab-vuln")
PATCHED_KID = os.getenv("PATCHED_KID", "lab-patched")

# Which key to use for signing tokens by default
DEFAULT_SIGN_KID = os.getenv("DEFAULT_SIGN_KID", PATCHED_KID)

def ensure_keys():
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Ensure vulnerable (legacy) keys exist (keep your current ones)
    if not LEGACY_SERVER_KEY.exists() or not LEGACY_PUBLIC_PEM.exists() or not LEGACY_RSA_JSON.exists():
        print("[*] Vulnerable (legacy) keys not found. Generating using:", VULN_KEYGEN)
        subprocess.check_call(["python", VULN_KEYGEN])
    else:
        print("[*] Existing vulnerable (legacy) keys found.")

    # Ensure patched keys exist (new)
    if not PATCHED_SERVER_KEY.exists() or not PATCHED_PUBLIC_PEM.exists():
        print("[*] Patched keys not found. Generating using:", PATCHED_KEYGEN)
        try:
            subprocess.check_call(["python", PATCHED_KEYGEN])
        except TypeError:
            # Fallback if Python <3.8 style env not supported in your runtime (rare)
            subprocess.check_call(["python", PATCHED_KEYGEN])
    else:
        print("[*] Existing patched keys found.")

ensure_keys()

app = Flask(__name__)

# -----------------------
# Helpers
# -----------------------
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))

def b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"\x00"
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def load_key_material():
    """
    Returns dict keyed by kid:
      {
        kid: {"priv_pem_path": Path, "pub_pem_path": Path, "pubkey": RSA.RsaKey}
      }
    """
    materials = {}

    # vulnerable (legacy)
    vuln_pub_pem = LEGACY_PUBLIC_PEM.read_text()
    materials[VULN_KID] = {
        "priv_pem_path": LEGACY_SERVER_KEY,
        "pub_pem_path": LEGACY_PUBLIC_PEM,
        "pubkey": RSA.import_key(vuln_pub_pem),
    }

    # patched
    patched_pub_pem = PATCHED_PUBLIC_PEM.read_text()
    materials[PATCHED_KID] = {
        "priv_pem_path": PATCHED_SERVER_KEY,
        "pub_pem_path": PATCHED_PUBLIC_PEM,
        "pubkey": RSA.import_key(patched_pub_pem),
    }

    return materials

KEYS = load_key_material()

def build_jwks():
    keys = []
    for kid, info in KEYS.items():
        pub = info["pubkey"]
        keys.append({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": b64url_uint(pub.n),
            "e": b64url_uint(pub.e),
        })
    return {"keys": keys}

def sign_jwt(payload: dict, kid: str | None = None) -> str:
    """Manual RS256 signing using PyCryptodome, with explicit kid."""
    use_kid = kid or DEFAULT_SIGN_KID
    if use_kid not in KEYS:
        raise ValueError(f"unknown signing kid: {use_kid}")

    header = {"alg": "RS256", "typ": "JWT", "kid": use_kid}
    header_b = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    signing_input = b"%s.%s" % (
        base64.urlsafe_b64encode(header_b).rstrip(b"="),
        base64.urlsafe_b64encode(payload_b).rstrip(b"="),
    )

    h = SHA256.new(signing_input)
    priv = RSA.import_key(KEYS[use_kid]["priv_pem_path"].read_text())
    sig = pkcs1_15.new(priv).sign(h)
    return signing_input.decode("ascii") + "." + b64url_encode(sig)

def verify_jwt(token: str):
    """Verify RS256 using local key store selected by kid. Reject unknown kid. Do NOT trust jku/x5u."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token format invalid")

    header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    kid = header.get("kid")
    if not kid:
        raise ValueError("missing kid")
    if kid not in KEYS:
        raise ValueError(f"unknown kid: {kid}")

    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    sig = b64url_decode(parts[2])
    h = SHA256.new(signing_input)

    pub = KEYS[kid]["pubkey"]
    pkcs1_15.new(pub).verify(h, sig)

    payload_json = b64url_decode(parts[1]).decode("utf-8")
    return json.loads(payload_json)

# -----------------------
# Routes
# -----------------------
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    return jsonify(build_jwks())

@app.route("/public.pem", methods=["GET"])
def public_pem():
    # Keep legacy endpoint for compatibility (vulnerable key public pem)
    return send_file(str(LEGACY_PUBLIC_PEM), mimetype="application/x-pem-file")

@app.route("/patched/public_patched.pem", methods=["GET"])
def patched_public_pem():
    return send_file(str(PATCHED_PUBLIC_PEM), mimetype="application/x-pem-file")

@app.route("/rsa.json", methods=["GET"])
def rsa_json():
    # Keep your debug endpoint as-is (legacy vulnerable components)
    data = json.loads(LEGACY_RSA_JSON.read_text())
    return jsonify(data)

@app.route("/token", methods=["GET"])
def token_endpoint():
    sub = request.args.get("sub", "attacker")
    role = request.args.get("role", "user")
    exp_seconds = int(request.args.get("exp", "3600"))

    # allow selecting which key signs the token (lab)
    kid = request.args.get("kid", DEFAULT_SIGN_KID)

    now = int(time.time())
    payload = {"sub": sub, "role": role, "iat": now, "exp": now + exp_seconds}
    token = sign_jwt(payload, kid=kid)
    return jsonify({"token": token, "kid": kid})

@app.route("/")
def index():
    now = int(time.time())

    payload_guest = {"sub": "guest", "role": "guest", "iat": now, "exp": now + 3600}

    # Create 2 tokens explicitly
    vuln_token = sign_jwt(payload_guest, kid=VULN_KID)
    patched_token = sign_jwt(payload_guest, kid=PATCHED_KID)

    html = f"""
    <h3>RSA lab HTTP server (dual keys: vuln + patched)</h3>

    <p>
      Cookies set:
      <code>auth_token</code> (kid=<code>{VULN_KID}</code>) and
      <code>auth_token_patched</code> (kid=<code>{PATCHED_KID}</code>)
    </p>

    <h4>Vulnerable token</h4>
    <p>kid: <code>{VULN_KID}</code></p>
    <textarea rows="4" cols="110" readonly>{vuln_token}</textarea>

    <h4>Patched token</h4>
    <p>kid: <code>{PATCHED_KID}</code></p>
    <textarea rows="4" cols="110" readonly>{patched_token}</textarea>

    <br><br>
    <ul>
      <li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a> — JWKS (both keys)</li>
      <li><a href="/public.pem">/public.pem</a> — legacy public key (vuln)</li>
      <li><a href="/patched/public_patched.pem">/patched/public_patched.pem</a> — patched public key</li>
      <li><a href="/rsa.json">/rsa.json</a> — (debug) legacy key components</li>
      <li><a href="/token">/token</a> — get JWT (supports ?kid={VULN_KID} or ?kid={PATCHED_KID})</li>
      <li><a href="/admin">/admin</a> — admin panel (reads cookie <code>auth_token</code> only)</li>
    </ul>
    <p><b>Note:</b> This server is for lab use only.</p>
    """

    resp = make_response(html)

    # Set two cookies
    resp.set_cookie("auth_token", vuln_token, httponly=False, samesite="Lax")
    resp.set_cookie("auth_token_patched", patched_token, httponly=False, samesite="Lax")

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
