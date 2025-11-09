# Modular Exponentiation

Trong quá trình thực hiện giải mã và mã hóa trong hệ mật mã RSA ta đều cần thực hiện phép tính lũy thừa với số mũ lớn. Điều này đòi hỏi việc thiết kế một thuật toán giúp tăng tốc độ tính toán. 
Một thuật toán thường được sử dụng trước đây đó chính là Square and Multiply. 

Chi tiết thuật toán như sau: 
<img width="708" height="353" alt="image" src="https://github.com/user-attachments/assets/3d423c9d-753b-49ea-97a2-93ee5a49ea7c" />

Trong đó $e$ là số mũ và $e_i$ chính là các chữ số của nó trong biểu diễn nhị phân:

$$
e = (e_{k-1}e_{k-2}...e_1e_0) = \sum_{i=0}^{k-1} e_i2^i
$$

Pseudo code bằng python như sau: 

```python
def square_and_mul(c, d, n):
    c %= n
    res = 1
    bit_time = []
    for bit in bin(d)[2:]:
        res = (res * res) % n  
        if bit == '1':
            res = (res * c) % n
    return res
```
Trong thuật toán trên, nếu như bit tại vị trí $k$ của $e$ đúng bằng 1 thì thuật toán sẽ thực hiện thêm một bước nhân kèm theo bước bình phương trước đó , còn ngược lại thì chỉ thực hiện bình phương. 

Điều này dẫn đến việc thời gian trung bình để tính toán giá trị tại bit 1 sẽ lâu hơn tại bit 0. 

Ta có thể mô phỏng lại một decryption oracle đơn giản như sau: 
```python
def decrypt_rsa(c, d, n):
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
    return res, bit_time
```

Oracle này thực hiện tính toán thuật toán lũy thừa ở trên và đo xem thời gian ở mỗi bước tính toán như vậy sẽ là bao nhiêu. 

Kế đến ta thực hiện truy vấn đến Oracle và gọi hàm giải mã đủ nhiều để thu thập số liệu:
```python
if __name__ == "__main__":
    results = []

    for i in range(750):
        m = random.randint(2, n - 2)
        c = pow(m, e, n)

        m_dec, times = decrypt_rsa(c, d, n)
        ok = (m_dec == m)

        per_bit = [t[1] + t[2] for t in times]
        total_time = sum(per_bit)

        results.append({
            "run": i,
            "ok": ok,
            "total_time_ns": total_time,
            "per_bit_time_ns": per_bit
        })
    with open("output.json", "w") as f:
        json.dump(results, f, indent=2)
```

Kế đến ta sẽ tính xem trung bình mỗi một lần chạy như vậy sẽ tốn trung bình bao nhiêu thời gian, ta gọi đây là ngưỡng (threshold). Nếu như thời gian chạy tại 1 bit cụ thể vượt quá ngưỡng thì bit đó sẽ "khả năng cao" là 1, còn ngược lại là bit 0. 

Do việc tính toán được thực hiện trực tiếp trên máy tính cá nhân nên số liệu có thể sai sót và không chắc chắn đúng hoàn toàn. 

```python
import json
import statistics

with open("output.json", "r") as f:
    runs = json.load(f)

num_runs = len(runs)
num_bits = len(runs[0]["per_bit_time_ns"])

mean_per_bit = []
for bit_idx in range(num_bits):
    samples = [runs[r]["per_bit_time_ns"][bit_idx] for r in range(num_runs)]
    mean_t = statistics.mean(samples)
    mean_per_bit.append(mean_t)

base_threshold = statistics.median(mean_per_bit)

def recover_bits(threshold):
    return "".join(
        "1" if mean_t > threshold else "0"
        for mean_t in mean_per_bit
    )

print("Số lần đo:", num_runs)
print("Số bit của d quan sát được:", num_bits)
print("Ngưỡng median:", base_threshold)
rec_median = recover_bits(base_threshold)
print("\n[median] Chuỗi bit d khôi phục ")
print(rec_median)
```

Ta cũng có thể viết thêm hàm một hàm đơn giản sau để tính khoảng cách Hamming giữa private key gốc $d$ và private key khôi phục được để xem thử có bao nhiêu bit sai lệch nhau:

```python
def check_diff(bin1:str,bin2:str) -> int:
    count = 0
    for i,(a,b) in enumerate(zip(bin1,bin2)):
        if a!=b:
            count +=1
            print(f"diff at {i}")
    return count
```

Nhận xét:

Do việc thống kê có thể xảy ra sai số cho nên không có cách cụ thể nào để chắc chắn khôi phục lại được $d$ hoàn toàn. Với số lần chạy tính toán càng nhiều thì số bit sai lệch giữa $d$ gốc và $d$ khôi phục được sẽ giảm dần. 

Ví dụ trong một lần chạy ta có thể khôi phục lại được hoàn toàn $d$ như sau: 

<img width="788" height="796" alt="image" src="https://github.com/user-attachments/assets/34bb0c6f-dbd0-43cc-aa36-8e58856579b5" />

Chỉ sai lệch nhau ở MSB, lí do cho việc này là trong quá trình tính toán, ta mặc định rằng số mũ luôn có MSB = 1, cho nên ở bước đầu tiên đã bỏ qua các bước lũy thừa và nhân dẫn thời gian tính toán nhanh hơn hẳn so với phần còn lại. 

Trong đa số các trường hợp khác thì số lượng bit sai lệch là khá nhiều. 

<img width="769" height="969" alt="image" src="https://github.com/user-attachments/assets/bb2ce1ea-41b7-4996-a03b-91e52b15b729" />


# Cải tiến

## Trường hợp thứ nhất




