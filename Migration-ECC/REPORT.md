# Chuẩn hóa sang ECC
Một số chuẩn chữ kí và mã hóa có thể được chuyển từ RSA sang ECC vì các lợi ích của nó. Một trong số những điểm mạnh của ECC so với RSA đó chính là kích thước khóa nhỏ. 

Bảng dưới đây cho biết độ lớn của khóa có ảnh hưởng như thế nào đến security level. Ta có thể thấy rằng ECC-256 bits cung cấp cho ta độ bảo mật tương đương với RSA-2048 bits nhưng kích thước khóa bí mật cần lưu trữ lại nhỏ hơn rất nhiều.

<img width="799" height="168" alt="image" src="https://github.com/user-attachments/assets/f24e0fec-424e-412d-abbd-3d4c48c38e7e" />


Ta có bảng so sánh sau đây về thời gian chạy một số phép tính toán trong RSA-2048 bits và ECC-256 bits với đường cong tiêu chuẩn sử dụng cho Bitcoin là $y^2=x^3+7$

| Thuật toán (worst-case theo script)                                  | Thời gian chạy (giây) |
| -------------------------------------------------------------------- | --------------------: |
| RSA modular exponentiation `pow(m, n-2, n)`                          |          0.0189222010 |
| ECC scalar multiplication over ( $\mathbb{F}_q$ )                      |          0.0018611840 |
| ECC scalar multiplication over ( $\mathbb{F}_{q^2}$ )                  |          0.7118690460 |
| Weil pairing over ( $\mathbb{F}_q$ )                                   |          0.0035008340 |
| Weil pairing over ( $\mathbb{F}_{q^2}$ )                               |          1.5980586600 |




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
# PKI và cách triển khai 
PKI cung cấp nền tảng bảo mật bằng cách sử dụng các cặp khóa bất đối xứng và chứng chỉ số. Trong trường hợp của ta thì thuật toán mã hóa bất đối xứng sẽ là ECC. Các quá trình tạo khóa, đăng ký và phát hành chứng chỉ, phân phối và lưu trữ chứng chỉ, xác thực danh tính, mã hóa và giải mã dữ liệu, chữ ký số và quản lý vòng đời chứng chỉ hoạt động đồng bộ để đảm bảo an ninh, tính toàn vẹn và xác thực trong các giao dịch và trao đổi thông tin trực tuyến.

Quy trình hoạt động của PKI như sau:
- Người dùng:
  - Tạo một cặp khóa gồm public key và private key
  - Public key được chia sẻ rộng rãi trong khi private key phải được giữ an toàn và bí mật
- Yêu cầu cấp chứng chỉ
  - Người dùng hoặc thiết bị gửi một yêu cầu chứng chỉ (Certificate Signing Request – CSR) đến một cơ quan chứng thực (Certificate Authority – CA).
  - Yêu cầu này bao gồm khóa công khai và thông tin nhận dạng của người dùng hoặc thiết bị.

CA sau đó sẽ xác minh danh tính của người dùng để đảm bảo rằng họ là người sử hữu hợp pháp của khóa công khai. CA sau đó sẽ cấp chứng chỉ cho người dùng. Nếu CA xác minh thành công danh tính của người dùng, họ sẽ cấp cho người dùng một chứng chỉ kĩ thuật số. Chứng chỉ này chứa thông tin về danh tính của người dùng và khóa công khai của họ và được kí bởi private key của CA. 

Chứng chỉ số này sau đó sẽ được gửi lại cho người dùng hoặc thiết bị, và có thể được phân phối cho bất kì ai cần xác thực danh tính của người dùng hoặc thiết bị đó. Khóa bí mật cần được giữ kín bởi người dùng hoặc thiết bị và không được chia sẻ với bất kì ai khác. 

Khi cần xác thực danh tính, người dùng hoặc thiết bị sẽ cung cấp chứng chỉ số của mình. Bên nhận sẽ kiểm tra chữ ký số trên chứng chỉ để xác nhận nó được phát hành bởi một CA đáng tin cậy. 

Bên nhận cũng cần xác minh khóa công khai trong chứng chỉ thuộc về người dùng hoặc thiết bị được nhận. 

Người dùng sử dụng khóa công khai để mã hóa thông tin: Khi cần gửi dữ liệu an toàn, bên gửi sử dụng khóa công khai của bên nhận (từ chứng chỉ số của bên nhận) để mã hóa dữ liệu. Chỉ bên nhận mới có thể giải mã dữ liệu này bằng khóa bí mật tương ứng.
# Triển khai các thuật toán chữ kí số bằng OpenSSL
Tham khảo tại: https://docs.openssl.org/3.1/man1/openssl-ec/#synopsis

Kiểm tra phiên bản OpenSSL hiện tại và xem các curve được hỗ trợ:
```bash
openssl version
openssl ecparam -list_curves
```
<img width="1195" height="694" alt="image" src="https://github.com/user-attachments/assets/4f9b49c9-53e1-4abb-b764-9f39e022a8c5" />

Tạo private key và public key dùng cho việc kí tin nhắn
```bash
openssl ecparam -name secp384r1 -genkey -noout -out private.key
openssl ec -in private.key -pubout -out public.pem
```
<img width="335" height="70" alt="image" src="https://github.com/user-attachments/assets/3f6d3498-53cb-4572-9f3d-45953f376869" />

Để kí một message bất kì, đầu tiên chuyển message đó vào file cần lưu:

```bash
echo "53edc760b7a66e1f4d8b0c5715725ee447b79c0" > hash.hexxxd -r -p hash.hex > hash.bin
```
Kí bằng private key:
```bash
openssl pkeyutl -sign -inkey private.key -in hash.bin -out signature.bin
```
Xem định dạng của file signature theo format ASN.1
```bash
openssl asn1parse -in signature.bin -inform der
```
<img width="1837" height="134" alt="image" src="https://github.com/user-attachments/assets/33283739-11c9-4705-900c-bed10b5aa70b" />

Đối với thuật toán kí bằng ECDSA, chữ kí số sẽ được lưu dưới dạng một cặp số $(r,s)$ 

Xác minh chữ kí bằng public key:
```bash
openssl pkeyutl -verify -inkey public.pem -pubin -in hash.bin -sigfile signature.bin
```
Thông báo thành công: 
<img width="1269" height="86" alt="image" src="https://github.com/user-attachments/assets/8aafcf5e-dbd0-4aef-8aa8-025dd1921f68" />

Giả sử ta muốn kí và xác minh trực tiếp cho một file bất kì thì có thể làm như sau:
```bash
echo "private message" > data.txt
openssl dgst -sha256 -sign private.key -out signature.bin data.txt
```
Xác minh bằng:
```bash
openssl dgst -sha256 -verify public.pem -signature signature.bin data.txt
```
Kết quả:
<img width="1131" height="152" alt="image" src="https://github.com/user-attachments/assets/da68355c-f8ad-4935-a62b-ca3776924920" />


Tiếp theo ta sẽ tạo chứng chỉ cho HTTP Server sử dụng thuật toán ECC. Ta sẽ sử dụng nginx cho HTTP Server.

Việc đầu tiên là tạo một private key mới cho server trong thư mục `/etc/nginx/ssl` và cấp quyền 600 cho nó:
```
cd /etc/nginx
sudo mkdir ssl
cd ssl
sudo openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:secp384r1 \
  -pkeyopt ec_param_enc:named_curve \
  -out server-ecc.key
sudo chmod 600 server-ecc.key
```
Xuất public key để gửi xác thực: 
```
sudo openssl pkey -in server-ecc.key -pubout -out server-ecc.pub.pem
```
Tạo một file cấu hình cho HTTP Server:
```
[ req ]
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
C  = VN
ST = HCM
L  = HCM
O  = Demo
OU = Crypto
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
```

Sau đó tạo file CSR
```
sudo openssl req -new -key server-ecc.key -out server.csr -config server.cnf
```
Ở đây ta sẽ đóng vai trò là Trusted CA để kí cho chứng chỉ của server
Tạo CA Key và CA cert:
```
sudo openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:secp384r1 \
  -pkeyopt ec_param_enc:named_curve \
  -out ca.key
sudo openssl req -x509 -new -key ca.key -sha256 -days 3650 \
  -subj "/C=VN/ST=HCM/L=HCM/O=DemoLab/OU=CA/CN=DemoLab Root CA" \
  -out ca.crt
sudo openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 \
  -extfile server.cnf -extensions req_ext
```
Tiếp theo ta cần cấu hình cho nginx server:
File cấu hình sẽ nằm trong thư mục `sites-available`
```
sudo nano default 
```
Đầu tiên là thêm mã trạng thái 301 cho HTTP để thông báo chuyển hướng vĩnh viễn URL của server này sang một địa chỉ URL mới. Ở đây ta sẽ redirect các kết nối HTTP sang HTTPS
```
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        # SSL configuration
        #
        # listen 443 ssl default_server;
        # listen [::]:443 ssl default_server;
        #
        # Note: You should disable gzip for SSL traffic.
        # See: https://bugs.debian.org/773332
        #
        # Read up on ssl_ciphers to ensure a secure configuration.
        # See: https://bugs.debian.org/765782
        #
        # Self signed certs generated by the ssl-cert package
        # Don't use them in a production server!
        #
        # include snippets/snakeoil.conf;

        # Add index.php to the list if you are using PHP

        server_name _;
        return 301 https://$host$request_uri;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }
}
```
Cuối cùng là cấu hình port 443 cho HTTPS:
```
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;

    server_name _;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server-ecc.key;

    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        try_files $uri $uri/ =404;
    }
}
```
Bước cuối cùng là import chứng chỉ CA đã được kí cho server để enable HTTPs. 

<img width="663" height="650" alt="image" src="https://github.com/user-attachments/assets/5c6324ec-39ba-489d-a851-b297f767b408" />

Chọn Trusted Root Certification Authorities.

Khởi động lại nginx:
```
sudo systemctl restart nginx
```
Kiểm tra chứng chỉ: 


<img width="398" height="300" alt="image" src="https://github.com/user-attachments/assets/0ea585a6-3081-4049-b4f0-6cfabee4078a" />
<img width="697" height="841" alt="image" src="https://github.com/user-attachments/assets/42d1db7d-16f7-4263-a91b-c7201a37356b" />

Hoặc cũng có thể check bằng `curl`:
```
curl --cacert /etc/nginx/ssl/ca.crt -vk https://localhost
```
