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

KEY_FILE = 'server_key.pem'
KEY_SIZE = 1024 # Dùng khóa 1024-bit cho PoC để chạy nhanh hơn

# Tạo hoặc tải khóa RSA
if os.path.exists(KEY_FILE):
    print("Loading existing RSA key...")
    with open(KEY_FILE, 'r') as f:
        key = RSA.import_key(f.read())
else:
    print(f"Generating new {KEY_SIZE}-bit RSA key...")
    key = RSA.generate(KEY_SIZE)
    with open(KEY_FILE, 'wb') as f:
        f.write(key.export_key('PEM'))

# Tạo một "bí mật" và mã hóa nó để làm mục tiêu (c0)
SECRET_MESSAGE = b'This is the secret pre-master-key!'
# Padding thủ công theo PKCS#1 v1.5 (cho mục đích demo)
# b'\x00\x02' + [padding string] + b'\x00' + [data]
pad_len = KEY_SIZE//8 - len(SECRET_MESSAGE) - 3
padded_secret = b'\x00\x02' + (b'A' * pad_len) + b'\x00' + SECRET_MESSAGE

# Dùng raw RSA (textbook RSA) để mã hóa
c0_int = pow(int.from_bytes(padded_secret, 'big'), key.e, key.n)
TARGET_CIPHERTEXT_HEX = hex(c0_int)[2:]

print(f"Target ciphertext (c0) for Attack A generated.")

# --- Khóa bí mật cho MAC (Cho Attack B) ---
HMAC_KEY = b'my_super_secret_hmac_key_12345'
print(f"HMAC secret key for Attack B initialized.")


# --- Các API endpoints ---

# === Endpoint cho Attack B (Timing) ===

@app.route('/check_mac', methods=['POST'])
def check_mac():
    """
    --- LỖ HỔNG (Attack B) ---
    Endpoint này so sánh MAC do user cung cấp với MAC đúng
    bằng một hàm so sánh *không* constant-time,
    dẫn đến timing leak.
    """
    data = request.json
    try:
        provided_mac_hex = data['mac']
        message = data['message']
        
        # Server tính toán MAC đúng
        correct_mac = hmac.new(HMAC_KEY, message.encode(), 'sha256').digest()
        provided_mac = binascii.unhexlify(provided_mac_hex)
        
        # --- HÀM SO SÁNH CÓ LỖ HỔNG (VULNERABLE) ---
        if len(correct_mac) != len(provided_mac):
            return jsonify({'error': 'Invalid MAC length'}), 400
            
        for i in range(len(correct_mac)):
            if correct_mac[i] != provided_mac[i]:
                # Trả về ngay khi phát hiện byte sai
                return jsonify({'error': 'Invalid MAC'}), 400
            
            # Giả lập một độ trễ nhỏ (5ms) cho MỖI BYTE ĐÚNG
            # Đây chính là "kênh rò rỉ" (leakage channel)
            time.sleep(0.005) 
            
        # Nếu tất cả các byte đều đúng:
        return jsonify({'status': 'MAC OK'}), 200

    except Exception as e:
        return jsonify({'error': f'Invalid request: {str(e)}'}), 400

if __name__ == '__main__':
    # Chạy server trên 0.0.0.0 để các container khác có thể truy cập
    app.run(host='0.0.0.0', port=5000, debug=False)

