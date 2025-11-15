from flask import Flask, jsonify, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import os
import binascii
import hmac
import hashlib
import time

# --- Khởi tạo Server và Khóa RSA (Cho Attack A) ---

app = Flask(__name__)

p = getPrime(512)
q = getPrime(512)
n = p * q

e = 65537
d = pow(e,-1,(p-1)*(q-1))
print(bin(d)[2:])


print(f"p={p}")
print(f"q={q}")
print(f"n={n}")
print(f"d={d}")


# --- Các API endpoints ---

# === Endpoint cho Attack B (Timing) ===

@app.route('/decrypt', methods=['POST'])
def decrypt_rsa():
    c = pow(m, e, n)
    try:
        c %= n
        res = 1
        bit_time = []
        for bit in bin(d)[2:]:
            t0 = time.perf_counter_ns()
            res = (res * res) % n
            t1 = time.perf_counter_ns()
            sq_time = t1 - t0

            mul_time = 0
            if bit == '1':
                t2 = time.perf_counter_ns()
                res = (res * c) % n
                t3 = time.perf_counter_ns()
                mul_time = t3 - t2

            bit_time.append((int(bit), sq_time, mul_time))
            data = {
                "res":res,
                "bit_time":bit_time
            }
        return jsonify(data),200
    except Exception as e:
        return jsonify({'error': f'Invalid request: {str(e)}'}), 400

if __name__ == '__main__':
    # Chạy server trên 0.0.0.0 để các container khác có thể truy cập
    app.run(host='0.0.0.0', port=5000, debug=False)

