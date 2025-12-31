#!/usr/bin/env python3
import gc, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, getRandomRange 

HOST = "0.0.0.0"
PORT = 5001
RSA_BITS = 64
PUBLIC_E = 65537
AMPLIFY = 500

def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def inv_mod(a: int, n: int) -> int:
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("no inverse")
    return x % n

def mont_params(n: int) -> Tuple[int, int]:
    k = n.bit_length()
    r = 1 << k
    r_inv = inv_mod(r, n)
    n_prime = (r * r_inv - 1) // n
    return r, n_prime

def mon_pro(a: int, b: int, n: int, n_prime: int, r: int):
    t = a * b
    m = (t * n_prime) % r
    u = (t + m * n) // r
    if u >= n:
        return u - n, True
    return u, False

def amp_mix(x: int, amplify: int) -> int:
    z = x
    for _ in range(amplify):
        z = ((z << 1) ^ (z >> 1) ^ 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
    return x ^ z

def rsa_sign_secure(m: int, d_bits: str, e: int, n: int, n_prime: int, r: int, amplify: int) -> int:
    # 1. BLINDING: Làm mù thông điệp đầu vào
    # m_blind = m * r_rand^e mod n
    r_rand = getRandomRange(1, n-1)
    blind_factor = pow(r_rand, e, n)
    r_inv_blind = inv_mod(r_rand, n) # Để unblind sau này
    
    m_blinded = (m * blind_factor) % n

    # 2. MONTGOMERY LADDER: Thuật toán mũ hóa cân bằng (Constant-flow)
    # Chuyển sang miền Montgomery
    m_bar = (m_blinded * r) % n
    
    R0 = r % n      # Đại diện cho 1
    R1 = m_bar      # Đại diện cho base
    
    # Duyệt từng bit (vẫn giữ nguyên amp_mix để mô phỏng leak phần cứng)
    # Nhưng cấu trúc code đối xứng giữa 0 và 1
    for bit in d_bits:
        if bit == '0':
            # Nhánh 0: R1 = R0*R1; R0 = R0*R0
            R1, sub1 = mon_pro(R0, R1, n, n_prime, r)
            if sub1 and amplify > 0: R1 = amp_mix(R1, amplify)
            
            R0, sub2 = mon_pro(R0, R0, n, n_prime, r)
            if sub2 and amplify > 0: R0 = amp_mix(R0, amplify)
        else:
            # Nhánh 1: R0 = R0*R1; R1 = R1*R1
            R0, sub1 = mon_pro(R0, R1, n, n_prime, r)
            if sub1 and amplify > 0: R0 = amp_mix(R0, amplify)
            
            R1, sub2 = mon_pro(R1, R1, n, n_prime, r)
            if sub2 and amplify > 0: R1 = amp_mix(R1, amplify)
            
    # Chuyển từ miền Montgomery về thường
    s_blinded, sub = mon_pro(R0, 1, n, n_prime, r)
    if sub and amplify > 0: s_blinded = amp_mix(s_blinded, amplify)

    # 3. UNBLIND: Gỡ bỏ lớp làm mù
    # s = s_blind * r_rand^-1 mod n
    sig = (s_blinded * r_inv_blind) % n
    
    return sig

class State:
    def __init__(self):
        self.p = getPrime(RSA_BITS//2)
        self.q = getPrime(RSA_BITS//2)
        self.n = self.p * self.q
        self.e = PUBLIC_E
        self.d = pow(self.e, -1, (self.p - 1)*(self.q - 1))
        self.d_bits = bin(self.d)[2:]
        self.r, self.n_prime = mont_params(self.n)

STATE = State()

class Handler(BaseHTTPRequestHandler):
    server_version = "SecureLaddderServer/2.0"

    def _json(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/pubkey":
            return self._json({"n": str(STATE.n), "e": str(STATE.e), "nbits": STATE.n.bit_length()})
        if self.path == "/debug":
            return self._json({"d": str(STATE.d), "d_bits": STATE.d_bits})
        if self.path == "/health":
            return self._json({"ok": True, "patched": True})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/sign":
            return self._json({"error": "not found"}, 404)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            req = json.loads(body.decode())
        except Exception:
            return self._json({"error": "invalid json"}, 400)
        msgs = req.get("messages")
        if not isinstance(msgs, list) or any(not isinstance(x, int) for x in msgs):
            return self._json({"error": "messages must be a list of int"}, 400)

        out = []
        for m in msgs:
            m_mod = m % STATE.n
            t0 = time.perf_counter_ns()
            
            sig = rsa_sign_secure(m_mod, STATE.d_bits, STATE.e, STATE.n, STATE.n_prime, STATE.r, AMPLIFY)
            
            t1 = time.perf_counter_ns()
            out.append({"m": m_mod, "sig": sig, "duration_ns": int(t1 - t0)})
        return self._json({"results": out})

def main():
    gc.disable()
    print("[server] http://%s:%d" % (HOST, PORT))
    print("[server] nbits=%d dbits=%d amplify=%d" % (STATE.n.bit_length(), len(STATE.d_bits), AMPLIFY))
    print("[server] d_bits = %s" % STATE.d_bits)
    HTTPServer((HOST, PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()