# Tài liệu
[1] [Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1](https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)


# Thuật toán 
## PKCS#1v1.5

Thay vì gửi nguyên msg ban đầu của ta thì ta sẽ pad thêm vào nó để làm cho quá trình mã hóa bằng RSA trở nên non-deterministic. 

Cụ thể: Gọi $\displaystyle k$ là byte-length của modulo $\displaystyle N$. Padding như sau:

- 2 bytes đầu tiên sẽ là `0x00` và `0x02`.
- Sau đó sẽ có ít nhất 8 random bytes theo sau và tất cả các bytes này khác `0x00`.
- Một byte `0x00` duy nhất sau đó
- Và cuối cùng là message cần pad.

<img width="783" height="125" alt="image" src="https://github.com/user-attachments/assets/6e90fcc6-2fbd-463e-9266-0735ee74d887" />

Hoặc nới lỏng hơn về điều kiện như sau:

<img width="965" height="400" alt="image" src="https://github.com/user-attachments/assets/6591a5fe-f528-4355-a21b-7e63dda27326" />


Toàn bộ quá trình Attacks diễn ra như sau:

Bây giờ ta muốn tính lại $\displaystyle m=c^{d}\bmod n$ trong đó $\displaystyle c$ là ciphertext. Đầu tiên ta sẽ chọn một số $\displaystyle s$ và tính 

$$\begin{equation*}
c'=s^{e} c\ (\bmod n)
\end{equation*}$$

và gửi $\displaystyle c'$ tới oracle. Oracle của ta ở đây đóng vai trò kiểm tra xem ciphertext sau khi giải mã có đúng theo định dạng PKCS như đã đề cập ở trên hay không. Nếu như oracle trả về kết quả là True thì ta biết rằng 2 bytes đầu tiên của messages là $\displaystyle 00$ và $\displaystyle 02$. Như vậy 

$$\begin{equation*}
2B\leqslant ms\bmod n\leqslant 3B
\end{equation*}$$

trong đó 

$$\begin{equation*}
B=2^{8( k-2)}
\end{equation*}$$

Đây là ý tưởng chính của attacks.

Có tổng cộng 3 phase. Ở phase đầu tiên, ta được cho $\displaystyle c_{0}$ là ciphertext của $\displaystyle m_{0}$ và message bị blinded. Phase tiếp theo ta sẽ tìm một giá trị $\displaystyle s_{i}$ sao cho ciphertext $\displaystyle c=c_{0}( s_{i})^{e}$ có chuẩn định dạng PKCS. Với mỗi giá trị $\displaystyle s_{i}$ ta sẽ tính được các khoảng giá trị $\displaystyle M=[ a,b]$ mà có thể chứa $\displaystyle m$. Phase cuối cùng, khi chỉ còn lại duy nhất một khoảng giá trị, lúc này ta có đầy đủ thông tin để đảm bảo rằng giá trị $\displaystyle s_{i}$ mà ta chọn sẽ thỏa mãn $\displaystyle c=c_{0}( s_{i})^{e}$ có định dạng chuẩn PKCS. Trong quá trình chọn thì giá trị của $\displaystyle s_{i}$ sẽ tăng lên, làm giảm range của các khoảng lại. 

**Bước 1.** Với ciphertext $\displaystyle c$, ta chọn random một giá trị $\displaystyle s_{0}$ và check oracle xem $\displaystyle c=c( s_{0})^{e}$ là đúng định dạng PKCS hay không. $\displaystyle s_{0}$ ban đầu mặc định là $\displaystyle 2$. 

Khi đã chọn được $\displaystyle s_{0}$ thỏa mãn thì ta set 

$$\begin{gather*}
c_{0}\leftarrow c( s_{0})^{e}\bmod n\\
M_{0}\leftarrow \{[ 2B,3B-1]\}\\
i\leftarrow 1
\end{gather*}$$

**Bước 2.** Gồm 3 trường hợp

2.a Nếu $\displaystyle i=1$ ta tìm $\displaystyle s_{1}$ nhỏ nhất sao cho $\displaystyle s_{1} \geqslant n/3B$ và $\displaystyle c_{0}( s_{1})^{e}$ có định dạng PKCS. 

2.b Nếu $\displaystyle i >1$ và có ít nhất 2 khoảng giá trị trong $\displaystyle M_{i-1}$ thì lúc này ta sẽ tìm $\displaystyle s_{i}  >s_{i-1}$ nhỏ nhất sao cho $\displaystyle c_{0}( s_{i})^{e}$ có định dạng PKCS.

2.c Khi chỉ còn đúng 1 khoảng giá trị trong $\displaystyle M_{i-1} =\{[ a,b]\}$ thì ta sẽ chọn các giá trị $\displaystyle r_{i} ,s_{i}$ sao cho 

$$\begin{equation*}
r_{i} \geqslant \frac{2( bs_{i-1} -2B)}{n}
\end{equation*}$$

và 

$$\begin{equation*}
\frac{2B+r_{i} n}{b} \leqslant s_{i} < \frac{3B+r_{i} n}{a}
\end{equation*}$$

cho tới khi $\displaystyle c_{0}( s_{i})^{e}\bmod n$ có định dạng PKCS. 

**Bước 3.** Giảm tập nghiệm. Với mỗi $\displaystyle s_{i}$ tìm được 

$$\begin{gather*}
M_{i} \leftarrow \bigcup_{( a,b,r)} 
\left\lbrace 
\left[ 
\max\left( a,\left\lceil \frac{2B+rn}{s_{i}} \right\rceil \right) ,
\min\left( b,\left\lfloor \frac{3B-1+rn}{s_{i}} \right\rfloor \right) 
\right] 
\right\rbrace \\
\forall [ a,b] \in M_{i-1} ,\quad 
\frac{a s_{i} -3B+1}{n} \leqslant r \leqslant \frac{b s_{i} -2B}{n}
\end{gather*}$$

**Bước 4.** Khi chỉ còn lại $\displaystyle M=[ a,b]$ thì ta sẽ kiểm tra xem $\displaystyle m\leftarrow a( s_{0})^{-1}\bmod n$ có phải giá trị ta mong muốn không. Nếu không thì tăng $\displaystyle i=i+1$.