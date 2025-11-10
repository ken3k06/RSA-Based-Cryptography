# Ngữ cảnh
Timing attack là dạng side-channel attack trong đó kẻ tấn công **không phá vỡ trực tiếp thuật toán mật mã**, mà khai thác:
- Thời gian thực thi khác nhau
- Do việc triển khai (implementation) phụ thuộc vào **giá trị bí mật**: khóa, bit của $d$, nhánh if, v.v.


Timing attack khả thi khi hội đủ các điều kiện sau:

1. **Có oracle / service thực thi phép toán mật mã**
   - Ví dụ:
     - Server cung cấp API giải mã RSA.
     - Thiết bị IoT / smartcard thực hiện ký số / giải mã.
     - TLS server dùng RSA private key để giải mã pre-master secret.

2. **Kẻ tấn công có thể gửi nhiều input tùy ý**
   - Chọn ciphertext khác nhau để đo.
   - Gửi nhiều lần cùng một ciphertext để giảm nhiễu.
 

3. **Đo được thời gian đủ chính xác**
   - Có thể là:
     - Local (cùng máy, cùng LAN) ⇒ độ chính xác cao.
     - Remote (qua mạng) ⇒ phải lấy **nhiều mẫu**, xử lý thống kê để triệt nhiễu.
   - Thời gian đo có tương quan với:
     - Bit của khóa bí mật.
     - Cấu trúc nhánh của thuật toán (square only vs square+multiply).
     - Việc xảy ra lỗi, early return, cache miss/hit,...



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

## Trường hợp thứ nhất: Các MSB đầu trùng nhau

Nếu xảy ra trường hợp có một số lượng lớn các MSB đầu trùng nhau, chẳng hạn: 

<img width="744" height="965" alt="image" src="https://github.com/user-attachments/assets/c44357c6-3ad2-45e0-a6ae-33478e435dc3" />

Thì ta có thể dùng kĩ thuật được đề cập trong bài báo sau đây để bẻ khóa hệ mật RSA: 
[Small Public Exponent Brings More: Improved Partial Key Exposure Attacks against RSA](https://eprint.iacr.org/2024/1329.pdf)

Định lý 1 phát biểu như sau:

**Định lý:** Cho hệ mật n-bit RSA với modulo $\displaystyle N=pq$ trong đó $\displaystyle q< p< 2q$ và $\displaystyle p-q= N^{\frac{1}{2} -\theta }$ trong đó $\displaystyle 0< \theta < \frac{1}{4}$ và $\displaystyle e=N^{\alpha }$ số mũ công khai RSA với $\displaystyle \alpha < \frac{1}{4}$. Đặt $\displaystyle d=N^{\delta }$ trong đó $\displaystyle d$ chính là số mũ bí mật RSA thỏa mãn $\displaystyle ed\equiv 1(\bmod( p-1)( q-1))$. Với $\displaystyle d_{0}$ là một xấp xỉ của $\displaystyle d$ thỏa mãn $\displaystyle |d-d_{0} |< N^{\gamma }$. Nếu ta biết thông tin về $\displaystyle d_{0}$ thì ta có thể phân tích thừa số nguyên tố $\displaystyle N$ trong thời gian đa thức nếu như: 

$$
\begin{equation*}
\gamma < \delta +\alpha -\theta -\frac{3}{4}
\end{equation*}
$$



<img width="726" height="144" alt="image" src="https://github.com/user-attachments/assets/46b1ed41-9139-4a1e-b785-4464fbdeadf6" />

Với $e=65537$ và modulo $n$ có độ lớn 1024 bit 

Từ điều kiện 

$$
\begin{equation*}
|d-d_{0} |< N^{\gamma } ,\ \gamma < \delta +\alpha -\theta -\frac{3}{4}
\end{equation*}
$$

Ta tính được số MSB cần thiết để khôi phục lại d như sau: 

Giả sử ta biết được $\displaystyle L$ MSB đầu của $\displaystyle d$ chính là $\displaystyle d_{0}$. Thì lúc này 

$$
\begin{gather*}
|d-d_{0} |< 2^{n-L} =2^{n} 2^{-L} \sim N2^{-L} =N^{1-L/n}\\
\Longrightarrow \gamma \sim 1-\frac{L}{n}
\end{gather*}
$$

Mà từ $\displaystyle \ \gamma < \delta +\alpha -\theta -\frac{3}{4}$ ta suy ra 

$$
\begin{equation*}
\frac{L}{n}  >\frac{7}{4} -\delta -\alpha +\theta 
\end{equation*}
$$

Với $\displaystyle e=65537$ nhỏ thì $\displaystyle \delta \sim 1$ do $\displaystyle d$ lớn và hơn hết $\displaystyle p,q$ được sinh theo tiêu chuẩn và có $\displaystyle \theta \sim 0$. Từ đây ta có thể xét 

$$
\begin{equation*}
L >n\left(\frac{3}{4} -\alpha \right)
\end{equation*}
$$

Với $\displaystyle \alpha =\frac{log_{2}( e)}{log_{2}( N)} \sim \frac{16}{1024} =0.015625$ thì ta có 

$$
\begin{equation*}
L >0.734375\times 1024\sim 752
\end{equation*}
$$

Vậy ta cần biết được ít nhất là $\displaystyle 752$ MSB của $\displaystyle d_{0}$ để có thể khôi phục lại $\displaystyle d$. 

Ta có thể thử demo một trường hợp như sau: 


```python
import time
import logging
from attacks.rsa.fnp import attack
from shared.partial_integer import PartialInteger
from sage.all import inverse_mod, next_prime, ZZ, PolynomialRing

logging.basicConfig(filename='attack.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

p=7574549438594602947916381661341324418847044954985441522282037156104740174840171156997363512275017589563515452727020685781080486409940827106768405176900421
q=9970598644345013977897839320766815949743231019225602345229756053597783349067472853383228934444309387945869937287308180451323940137496715758890046325910153
N=75522792363975634850806847194815276560209889276663760591114529719605903546230023554630324910395438937331646351431533159399126123167644926133888263020892870885733908195509322385393046826503701316104357415521683686189269763222034867442000759015304386210301619559134560681719942503299368975051896878974273874413
phi = (p - 1) * (q - 1)

ebits = 17
msbs = 752
enumeration = 6
m=75
thetaLogN = 2
 
e = 2**(ebits-1) + 1
d = inverse_mod(e, phi)
k= int((e*d-1)/phi)

ifFlatter = True

start_time = time.time()
result = attack(N, e, PartialInteger.msb_of(d, 1024, msbs), m=m, k=k, thetaLogN=thetaLogN,  enumeration=enumeration, ifFlatter=ifFlatter, p=p)
print(result)
print("Time:",time.time()-start_time)


# ebits MSBs m thetaLogN time
# 17 758 55 2 14.34
# 17 756 100 2 126.67

'''

ebits = 17
msbs = 752
enumeration = 6
m=75
thetaLogN = 2

ebits = 129
msbs = 640
enumeration = 6
m=75
thetaLogN = 2

ebits = 257
msbs = 512
enumeration = 8
m=75
thetaLogN = 4
'''
```
<img width="748" height="817" alt="image" src="https://github.com/user-attachments/assets/a91d3931-5df0-48ac-b918-e0b4b668bb42" />

# Khắc phục 



