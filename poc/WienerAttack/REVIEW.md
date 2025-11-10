# Ngữ cảnh cho Wiener's Attack

## 1. Mục tiêu

Wiener’s attack nhắm vào các hệ RSA được cấu hình **không an toàn**, cụ thể là khi **số mũ bí mật $d$ quá nhỏ so với mô-đun $N$**.  
Trong trường hợp này, kẻ tấn công có thể **khôi phục trực tiếp $d$** chỉ từ khóa công khai $(N, e)$, **không cần side-channel, không cần oracle**.

---

## 2. Mô hình hệ thống

Xét hệ RSA chuẩn:

- $N = pq$, với $p, q$ là số nguyên tố lớn, có số bit xấp xỉ nhau.
- $\varphi(N) = (p-1)(q-1)$.
- Khóa công khai: $(N, e)$, với $\gcd(e, \varphi(N)) = 1$.
- Khóa bí mật: $d$ thỏa:

$$
ed \equiv 1 \pmod{\varphi(N)}.
$$

Trong triển khai an toàn, $d$ thường có kích thước gần $\varphi(N)$ (xấp xỉ $|N|$ bit).  
Tuy nhiên, một số hệ thống cũ, thiết bị nhúng hoặc code tự viết có thể **cố tình chọn $d$ nhỏ để giải mã nhanh**, và đây là đúng vùng nguy hiểm của Wiener.

---

## 3. Điều kiện tấn công

Wiener chứng minh rằng tấn công thành công (và rất nhanh) nếu:

$$
d < \frac{1}{3} N^{1/4}
$$

với giả thiết RSA chuẩn: $p, q$ có kích thước gần nhau.

Nói nôm na:

> Nếu $d$ nhỏ hơn cỡ $N^{1/4}$ (chia 3) thì hệ RSA gần như **chắc chắn bị phá** bằng Wiener's attack.

---

## 4. Ý tưởng tấn công (trực giác)

Từ phương trình khóa:

$$
ed - k\varphi(N) = 1
$$

suy ra:

$$
\frac{e}{\varphi(N)} \approx \frac{k}{d}.
$$

Khi $d$ rất nhỏ, phân số $\dfrac{k}{d}$ xuất hiện như **một convergent** trong phân số liên tục (continued fraction) của $\dfrac{e}{N}$ (vì $\varphi(N) \approx N$).

Thuật toán Wiener (rất gọn):

1. Tính continued fraction của $\dfrac{e}{N}$.
2. Duyệt các convergent $\dfrac{k_i}{d_i}$.
3. Với mỗi $d_i$, kiểm tra xem có suy ra được $\varphi(N)$ rồi $p, q$ hay không.
4. Nếu đúng, ta khôi phục được toàn bộ khóa bí mật.

Toàn bộ thuật toán chạy thời gian đa thức và cực nhanh trong thực tế.

---

## 5. Khi nào Wiener **không** áp dụng được

Wiener’s attack **không hiệu quả** nếu:

- $d$ **được chọn đủ lớn**, không thỏa điều kiện $d < N^{1/4} / 3$.
- Hệ thống dùng $e = 65537$ (nhỏ) **nhưng $d$** vẫn full-size chuẩn (như trong hầu hết hệ thống hiện đại).
- Các kịch bản **partial key exposure**:
  - chỉ lộ một phần MSB/LSB của $d$,
  - một vài bit của $d$ bị lật (bit flip),
  - side-channel timing, padding oracle, Bleichenbacher, v.v.

Những trường hợp này thuộc phạm vi của Boneh–Durfee, Blömer–May, Ernst, Feng–Nitaj–Pan…, **không phải** Wiener's attack thuần túy.

---

## 6. Hệ thống nào dễ dính Wiener

Các dấu hiệu nguy hiểm:

- Tự ý “tối ưu” bằng cách chọn $d$ nhỏ hơn nhiều so với $|N|$.
- Thiết bị nhúng, smart card, firmware tự cài RSA **không theo chuẩn**.
- RSA key 1024-bit nhưng (nếu kiểm tra được) $d$ chỉ khoảng vài trăm bit.

Nếu điều kiện $d < N^{1/4} / 3$ thỏa, có thể coi hệ thống **gần như vỡ hoàn toàn**.

---

## 7. Phòng tránh

- **Không bao giờ chọn $d$ nhỏ** một cách tùy tiện.
- Tuân thủ chuẩn sinh khóa RSA (FIPS, PKCS#1).
- Dùng CRT-RSA đúng cách: tối ưu hiệu năng bằng $d_p, d_q$, không phải bằng cách làm $d$ toàn cục quá nhỏ.
- Kiểm tra an toàn: nếu phát hiện $d$ (hoặc thiết kế) vi phạm điều kiện Wiener → **thu hồi, thay khóa**.

---

## 8. Tóm tắt

- Wiener's attack là tấn công **thuần toán học, không cần side-channel**.
- Điều kiện chính: **$d$ quá nhỏ**.
- Trong các hệ thống tuân chuẩn hiện đại (với $d$ đủ lớn), rủi ro từ Wiener's attack gần như bị loại bỏ hoàn toàn.
