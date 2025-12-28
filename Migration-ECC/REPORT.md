# Chuẩn hóa sang ECC
Một số chuẩn chữ kí và mã hóa có thể được chuyển từ RSA sang ECC vì các lợi ích của nó. Một trong số những điểm mạnh của ECC so với RSA đó chính là kích thước khóa nhỏ. 

Bảng dưới đây độ lớn của khóa có ảnh hưởng như thế nào đến security level. Ta có thể thấy rằng ECC-256 bits cung cấp cho ta độ bảo mật tương đương với RSA-2048 bits nhưng kích thước khóa bí mật cần lưu trữ lại nhỏ hơn rất nhiều.

<img width="799" height="168" alt="image" src="https://github.com/user-attachments/assets/f24e0fec-424e-412d-abbd-3d4c48c38e7e" />


Ta có bảng so sánh sau đây về thời gian chạy một số phép tính toán trong RSA-2048 bits và ECC-256 bits với đường cong tiêu chuẩn sử dụng cho Bitcoin là $y^2=x^3+7$

| Thuật toán (worst-case theo script)                                  | Thời gian chạy (giây) |
| -------------------------------------------------------------------- | --------------------: |
| RSA modular exponentiation `pow(m, n-2, n)`                          |          0.0189222010 |
| ECC scalar multiplication over ( $\mathbb{F}_q$ ) `G*(q-2)`            |          0.0018611840 |
| ECC scalar multiplication over ( $\mathbb{F}_{q^2}$ ) `G_quad*(q^2/2)` |          0.7118690460 |
| Weil pairing over ( $\mathbb{F}_q$ )                                   |          0.0035008340 |
| Weil pairing over ( $\mathbb{F}_{q^2}$ )                               |          1.5980586600 |

*Bảng: Thời gian chạy “worst-case” (theo phép chọn số mũ/scalar trong script) cho RSA, ECC trên ( \mathbb{F}*q ), ECC trên ( \mathbb{F}*{q^2} ), và Weil pairing trên ( \mathbb{F}*q )/( \mathbb{F}*{q^2} ).*


Code demo: 
```python
from Crypto.Util.number import * 
from sage.all import * 
import timeit 
p = getPrime(1024)
q = getPrime(1024)
n = p*q 
m = int(n//2)
k = n - 2 # worst cases
start = timeit.default_timer()
print(f"Result mod pow : = {pow(m,k,n)}")
end = timeit.default_timer()
print(f"Time for RSA: {end - start} seconds")

# ECC for Bitcoin system 
q = 115792089237316195423570985008687907853269984665640564039457584007908834671663
E = EllipticCurve(GF(q), [0, 7])
G = E(55066263022277343669578718895168534326250603453777594175500187360389116729240, 
    32670510020758816978083085130507043184471273380659243275938904335757337482424)
k = q - 2 # worst cases
start = timeit.default_timer()
print(f"Result ECC pow: = {G*k}")
end = timeit.default_timer()
print(f"Time for ECC: {end - start} seconds")
n = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

F = PolynomialRing(GF(q), name = 'x')
x = F.gen()
f = x**2 + 1 
K = F.quotient(f)
E_quad = EllipticCurve(K, [0, 7])
G_quad = E_quad(K(55066263022277343669578718895168534326250603453777594175500187360389116729240), 
    K(32670510020758816978083085130507043184471273380659243275938904335757337482424))
k = int(q**2//2) # worst cases
start = timeit.default_timer()
print(f"Result ECC over quad pow: = {G_quad*k}")
end = timeit.default_timer()
print(f"Time for ECC over quad: {end - start} seconds")

# Weil pairing over finite field
a = ZZ.random_element(1, n)
b = ZZ.random_element(1, n)
P = a*G
Q = b*G
start = timeit.default_timer()
e_PQ = P.weil_pairing(Q, n, algorithm =None)
end = timeit.default_timer()
print(f"Weil pairing: {e_PQ}")
print(f"Time for Weil pairing F_q: {end - start} seconds")


# Weil pairing over quad field
a = ZZ.random_element(1, n)
b = ZZ.random_element(1, n)
P = a*G_quad
Q = b*G_quad
start = timeit.default_timer()
e_PQ = P.weil_pairing(Q, n, algorithm ='sage')
end = timeit.default_timer()
print(f"Weil pairing: {e_PQ}")
print(f"Time for Weil pairing F_q^2: {end - start} seconds")
```

# Triển khai các thuật toán chữ kí số bằng OpenSSL
