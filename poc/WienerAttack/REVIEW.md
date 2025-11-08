# Wiener's Attack - RSA
**Định lí (M.Wiener)** Cho $\displaystyle N=pq$ là một số nguyên dương với $\displaystyle p,q$ là hai số nguyên tố thỏa mãn $\displaystyle q< p< 2q$. Với $\displaystyle d< \frac{1}{3} N^{1/4}$, nếu ta biết cặp giá trị $\displaystyle ( N,e)$ và $\displaystyle ed\equiv 1(\bmod \varphi ( N))$ thì từ đó ta có thể tính được giá trị của $\displaystyle d$.


# Cơ sở toán học
Với mỗi số hữu tỉ $\displaystyle \frac{u}{v}$ thì ta có biểu diễn duy nhất dưới dạng liên phân số hữu hạn như sau: 

$$
\frac{u}{v} =x_{0} +\frac{1}{x_{1} +\frac{1}{\ddots +\frac{1}{x_{n}}}}
$$

trong đó $\displaystyle x_{0}$ là một số nguyên và các số $\displaystyle x_{i} ,i\geqslant 1$ đều là các số nguyên dương. Để biểu diễn một số hữu tỉ $\displaystyle \frac{u}{v}$ về dạng liên phân số hữu hạn thì ta có thể sử dụng thuật toán Euclid cho cặp số $\displaystyle ( u,v)$. Như vậy, với mỗi số $\displaystyle c_{i}$ được xác định bởi 

$$
\begin{equation*}
c_{0} =x_{0} ,c_{1} =x_{0} +\frac{1}{x_{1}} ,...,c_{n} =x_{0} +\frac{1}{x_{1} +\frac{1}{\ddots +\frac{1}{x_{n}}}}
\end{equation*}
$$

thì ta gọi $\displaystyle c_{i}$ là xấp xỉ liên phân số thứ $\displaystyle i$ của $\displaystyle \frac{u}{v}$. Để viết ra toàn bộ các xấp xỉ liên phân số của $\displaystyle \frac{u}{v}$ thì ta cần thực hiện tính toán thuật toán Euclid trong khoảng $\displaystyle O(\log(\max( u,v)))$. Như vậy thuật toán chạy khá tốt. 

Để tính toán giá trị của $\varphi(N)$ ta cũng dựa vào ý tưởng phân tích ra dạng liên phân số hữu hạn như trên. 
Đầu tiên ta dựa vào phương trình đồng dư $\displaystyle ed\equiv 1(\bmod \varphi ( N)$ suy ra được $\displaystyle ed-k\varphi ( N) =1$ với $\displaystyle k\in \mathbb{Z}^{+}$. Như vậy ta có thể viết lại dưới dạng 

$$
\begin{equation*}
\Bigl|\frac{e}{\varphi ( N)} -\frac{k}{d}\Bigl| =\frac{1}{d\varphi ( N)}
\end{equation*}
$$


Như vậy $\displaystyle \frac{k}{d}$ có thể xem như là một xấp xỉ của $\displaystyle \frac{e}{\varphi ( N)}$. Trường hợp này ta không biết giá trị của $\displaystyle \varphi ( N)$ nên ta có thể sử dụng $\displaystyle N$ để thực hiện phép xấp xỉ như sau : chú ý rằng ta đang có $\displaystyle d< \frac{1}{3} N^{\frac{1}{4}}$ và từ $\displaystyle q< p< 2q$ ta có được các đánh giá sau : $\displaystyle \varphi ( N) =N-p-q+1$ và ta có $\displaystyle N >q^{2} ,N >\frac{p^{2}}{2}$ cho nên $\displaystyle p+q-1< \left(\sqrt{2} +1\right)\sqrt{N} < \sqrt{N}$ kéo theo $\displaystyle |N-\varphi ( N) |< 3\sqrt{N}$. Từ đây ta có 

$$
\begin{gather*}
\Bigl|\frac{e}{N} -\frac{k}{d}\Bigl| =\Bigl|\frac{ed-kN}{Nd}\Bigl| =\Bigl|\frac{ed-k\varphi ( N) -kN+k\varphi ( N)}{Nd}\Bigl|\\
=\Bigl|\frac{1-k( N-\varphi ( N))}{Nd}\Bigl| \leqslant \Bigl|\frac{3k\sqrt{N}}{Nd}\Bigl| =\Bigl|\frac{3k}{\sqrt{N} d}\Bigl|
\end{gather*}
$$

Ta có $\displaystyle k\varphi ( N) =ed-1$ mà $\displaystyle \varphi ( N) < e$ nên ta có đánh giá $\displaystyle k=\frac{ed-1}{\varphi ( N)} < d$ vì $\displaystyle ed-1< d\varphi ( N)$ tương đương với $\displaystyle e-\frac{1}{d} < \varphi ( N)$ vì $\displaystyle e\leqslant \varphi ( N) -1$ dẫn tới $\displaystyle k< d< \frac{1}{3} N^{\frac{1}{4}}$ cho nên ta có 

$$
\begin{equation*}
\Bigl|\frac{e}{N} -\frac{k}{d}\Bigl| < \frac{3k}{\sqrt{N} d} \leqslant \frac{N^{\frac{1}{4}}}{N^{\frac{1}{2}} d} =\frac{1}{dN^{\frac{1}{4}}} < \frac{1}{2d^{2}}
\end{equation*}
$$

Để hoàn thiện chứng minh cho kết quả trên ta cần nhắc lại một số thứ như sau:

## Phân số liên tục 
Cho $\displaystyle \alpha =\alpha_{0}$ là một số thực. Ta sẽ xây dựng các số tự nhiên $\displaystyle a_{0} ,a_{1} ,...\in \mathbb{N}$ như sau:
1) Ta lấy $\displaystyle a_{0} =\lfloor \alpha_{0}\rfloor$ là phần nguyên của $\displaystyle \alpha_{0}$. Nếu $\displaystyle a_{0} =\alpha_{0}$ thì chứng tỏ rằng $\displaystyle \alpha_{0}$ là một số nguyên. Khi đó thuật toán dừng ở đây. Trong trường hợp nó không là số nguyên thì ta lấy $\displaystyle \alpha_{0} -a_{0} \in ( 0;1)$ và ta đặt 

$$
\begin{equation*}
\alpha_{1} =\frac{1}{\alpha_{0} -a_{0}}  >1
\end{equation*}
$$

Khi đó ta có $\displaystyle \alpha =a_{0} +\frac{1}{\alpha_{1}}$

2) Ta lại lấy $\displaystyle a_{1} =\lfloor \alpha_{1}\rfloor$ và làm tương tự như vậy, nếu như $\displaystyle a_{1}$ nguyên thì thuật dừng lại. Còn ngược lại nếu như $\displaystyle \alpha_{1} -a_{1} \in ( 0;1)$ thì ta đặt $\displaystyle \alpha_{2} =\frac{1}{\alpha_{1} -a_{1}}$ thì được $\displaystyle \alpha_{1} =a_{1} +\frac{1}{\alpha_{2}}$ và được về 

$$
\begin{equation*}
\alpha =a_{0} +\frac{1}{a_{1} +\frac{1}{\alpha_{2}}}
\end{equation*}
$$


Tiếp tục đặt $\displaystyle a_{2} =\lfloor \alpha_{2}\rfloor$. Tiếp tục như vậy ta sẽ xây dựng được một dãy các số tự nhiên $\displaystyle a_{1} ,a_{2} ,...,a_{n}$ và các số $\displaystyle \alpha _{i}$ định nghĩa bởi 

$$
\begin{equation*}
\alpha _{n+1} =\frac{1}{\alpha _{n} -a_{n}}  >1
\end{equation*}
$$


Còn đối với $\alpha$ là số hữu tỉ thì thuật toán trên sẽ dừng lại sau hữu hạn bước. Với $\displaystyle \alpha =\frac{a}{b}$, thì thuật toán để biểu diễn $\displaystyle \alpha$ dưới dạng liên phân số sẽ diễn ra như sau: Đầu tiên ta thực hiện phép chia $\displaystyle a$ cho $\displaystyle b$ thì được 

$$
\begin{gather*}
a=a_{0} b+r_{0}\\
b=a_{1} r_{0} +r_{1}\\
r_{0} =a_{2} r_{1} +r_{2}\\
r_{1} =a_{3} r_{2} +r_{3}\\
...\\
r_{n-2} =a_{n} r_{n-1} +1
\end{gather*}
$$

Tiến trình ở trên chính là thuật toán Euclid để tìm ước chung lớn nhất của $\displaystyle ( a,b)$. Ta sẽ dừng quá trình chia như trên cho tới khi phần dư thứ $\displaystyle n$ là $\displaystyle r_{n} =1$. Như vậy ta có được 

$$
\begin{gather*}
\frac{a}{b} =a_{0} +\frac{r_{0}}{b} =a_{0} +\frac{1}{\frac{b}{r_{0}}} =a_{0} +\frac{1}{a_{1} +\frac{r_{1}}{r_{0}}}\\
=a_{0} +\frac{1}{a_{1} +\frac{1}{\frac{r_{0}}{r_{1}}}} =a_{0} +\frac{1}{a_{1} +\frac{1}{a_{2} +\frac{r_{2}}{r_{1}}}} =....
\end{gather*}
$$

Như ta đã khảo sát ở trên thì thuật toán để biểu diễn một số hữu tỉ $\displaystyle \frac{a}{b}$ thực chất là thuật toán Euclid. Để nghiên cứu thêm về thuật toán này, trước hết ta cần thiết lập một số công thức đại số liên quan đến biểu thức phân số liên tục hay còn gọi là liên phân số. 


$$
\begin{equation*}
\xi _{m} =\langle a_{0} ,\dotsc ,a_{m}\rangle :=a_{0} +\frac{1}{a_{1} +\frac{1}{a_{2} +\frac{1}{\cdots +\frac{1}{a_{m}}}}} .
\end{equation*}
$$

Với $a_{0},...,a_{m}$ là các biến số độc lập. Với mọi $\displaystyle -1\leqslant n\leqslant m$, ta xây dựng các đa thức $\displaystyle p_{n} ,q_{n}$ với biến số $\displaystyle a_{0} ,...,a_{n}$ bằng quy nạp như sau: 

Với $\displaystyle n=-1$ ta đặt 

$$
\begin{equation*}
p_{-1} =1\ \text{và} \ q_{-1} =0
\end{equation*}
$$

 Với $\displaystyle n=0$ ta đặt 

 $$
\begin{equation*}
p_{0} =a_{0} \ \text{và} \ q_{0} =1
\end{equation*}
$$

Cuối cùng với $\displaystyle n >0$ ta đặt :

$$
\begin{gather*}
p_{n} =a_{n} p_{n-1} +p_{n-2}\\
q_{n} =a_{n} q_{n-1} +q_{n-2}
\end{gather*}
$$

và 

$$
\begin{equation*}
\frac{p_{n}}{q_{n}} =\langle a_{0} ,\dotsc ,a_{n}\rangle =a_{0} +\frac{1}{a_{1} +\frac{1}{a_{2} +\frac{1}{\cdots +\frac{1}{a_{n}}}}} .
\end{equation*}
$$

Ta có kết quả sau: 

**Tính chất** : Cho $\displaystyle a_{0} ,a_{1} ,...,a_{m}$ là các biến số độc lập. Với mọi số nguyên $\displaystyle n$ thỏa mãn $\displaystyle -1\leqslant n\leqslant m$ và các đa thức $\displaystyle p_{n} ,q_{n}$ được định nghĩa như trên thì ta sẽ có 

$$
\begin{equation*}
p_{n} q_{n-1} -q_{n} p_{n-1} =( -1)^{n}
\end{equation*}
$$

và 

$$
\begin{equation*}
\frac{p_{n}}{q_{n}} =\langle a_{0} ,\dotsc ,a_{n}\rangle =a_{0} +\frac{1}{a_{1} +\frac{1}{a_{2} +\frac{1}{\cdots +\frac{1}{a_{n}}}}} .
\end{equation*}
$$

*Chứng minh*


Từ công thức truy hồi của $\displaystyle p_{n} ,q_{n}$ ta có 

$$
\begin{gather*}
p_{n} q_{n-1} -q_{n} p_{n-1} =p_{n}\frac{q_{n} -q_{n-2}}{a_{n}} -q_{n}\frac{p_{n} -p_{n-2}}{a_{n}}\\
=\frac{q_{n} p_{n-2} -p_{n} q_{n-2}}{a_{n}} =\frac{p_{n-2}( a_{n} q_{n-1} +q_{n-2}) -q_{n-2}( a_{n} p_{n-1} +p_{n-2})}{a_{n}}\\
=\frac{a_{n}( q_{n-1} p_{n-2} -q_{n-2} p_{n-1})}{a_{n}} =-( p_{n-1} q_{n-2} -q_{n-1} p_{n-2})\\
=...=( -1)^{n}( p_{0} q_{-1} -q_{0} p_{-1})
\end{gather*}
$$

Vế phải của công thức này đúng bằng $\displaystyle ( -1)^{n-1}$. Tiếp theo ta chứng minh ý còn lại bằng cách quy nạp. 

Đầu tiên ta kiểm tra đẳng thức đúng với $\displaystyle n=0,n=1$. Ta áp dụng công thức sau 

$$
\begin{equation*}
\langle a_{0} ,a_{1} ,...,a_{n} ,a_{n+1} \rangle =\langle a_{0}^{'} ,a_{1}^{'} ,...,a_{n}^{'} \rangle 
\end{equation*}
$$

Với $\displaystyle a_{0} =a_{0}^{'} ,...,$ và $\displaystyle a_{n}^{'} =a_{n} +\frac{1}{a_{n+1}}$.

Theo giả thiết quy nạp ta có 

$$
\begin{equation*}
\langle a_{0}^{'} ,a_{1}^{'} ,...,a_{n}^{'} \rangle =\frac{p'_{n}}{q'_{n}}
\end{equation*}
$$

với 

$$
\begin{gather*}
p'_{n} =a'_{n} p_{n-1} +p_{n-2}\\
q'_{n} =a'_{n} q_{n-1} +q_{n-2}
\end{gather*}
$$

Thay $\displaystyle a'_{n}$ bằng vế phải như ở trên thì ta có 

$$
\begin{gather*}
\frac{\left( a_{n} +\frac{1}{a_{n+1}}\right) p_{n-1} +p_{n-2}}{\left( a_{n} +\frac{1}{a_{n+1}}\right) q_{n-1} +q_{n-2}} =\frac{a_{n} p_{n-1} +\frac{p_{n-1}}{a_{n+1}} +p_{n-2}}{a_{n} q_{n-1} +\frac{q_{n-1}}{a_{n+1}} +q_{n-2}}\\
=\frac{p_{n} +\frac{p_{n-1}}{a_{n+1}}}{q_{n} +\frac{q_{n-1}}{a_{n+1}}} =\frac{a_{n+1} p_{n} +p_{n-1}}{a_{n+1} q_{n} +q_{n-1}} =\frac{p_{n+1}}{q_{n+1}}
\end{gather*}
$$

Như vậy ta có được điều phải chứng minh. 

Phân số liên tục cho phép người ta tìm được xấp xỉ tốt nhất của một số thực $\displaystyle \alpha$ theo định nghĩa như sau: Với mọi $\displaystyle n\geqslant 0$ ta có 

$$
\begin{equation*}
\Bigl| \alpha -\frac{p_{n}}{q_{n}}\Bigl| < \frac{1}{q_{n}^{2}}
\end{equation*}
$$


Ngược lại nếu như $\displaystyle \frac{p}{q}$ thỏa mãn 

$$
\begin{equation*}
\Bigl| \alpha -\frac{p}{q}\Bigl| < \frac{1}{2q^{2}}
\end{equation*}
$$

thì $\displaystyle \frac{p}{q}$ phải là phần tử của dãy $\displaystyle \xi_{n} =\frac{p_{n}}{q_{n}}$. Và ngoài ra, trong 3 phân số liên tiếp $\displaystyle \xi _{n} ,\xi _{n+1} ,\xi _{n+2}$ luôn có ít nhất một phân số $\displaystyle \frac{p}{q}$ mà 

$$
\begin{equation*}
\Bigl| \alpha -\frac{p}{q}\Bigl| < \frac{1}{\sqrt{5} q^{2}}
\end{equation*}
$$

*Chứng minh các kết quả trên*

Ta có dãy bất đẳng thức sau đối với $\displaystyle \alpha$ và các xấp xỉ của nó 

$$
\begin{equation*}
\frac{p_{0}}{q_{0}} < \frac{p_{2}}{q_{2}} < ...< \alpha < ...< \frac{p_{3}}{q_{3}} < \frac{p_{1}}{q_{1}}
\end{equation*}
$$

tức là dãy $\displaystyle (\xi_{2n})_{n\geqslant 0}$ là dãy tăng và dãy $\displaystyle (\xi_{2n+1})_{n\geqslant 0}$ là dãy giảm và cả hai cùng hội tụ về $\displaystyle \alpha$. Như vậy các giản phân của số thực $\displaystyle \alpha$ tạo thành 2 dãy tịnh tiến về nhau và đồng thời ta có mỗi giản phân chẵn đều nhỏ hơn mỗi giản phân lẻ. 

Lý do có được kết quả trên là từ đẳng thức 

$$
\begin{equation*}
\xi _{2m} -\xi _{2m-1} =\frac{( -1)^{2m-1}}{q_{2m} q_{2m-1}} < 0\Longrightarrow \xi _{2m} < \xi _{2m-1}
\end{equation*}
$$

Bây giờ ta có với $\displaystyle n$ chẵn thì 

$$
\begin{equation*}
\frac{p_{n}}{q_{n}} < \alpha < \frac{p_{n+1}}{q_{n+1}}
\end{equation*}
$$

Khi đó 

$$
\begin{equation*}
0< \alpha -\frac{p_{n}}{q_{n}} < \frac{p_{n+1}}{q_{n+1}} -\frac{p_{n}}{q_{n}} =\frac{1}{q_{n} q_{n+1}} < \frac{1}{q_{n}^{2}}
\end{equation*}
$$

Và tương tự với $\displaystyle n$ lẻ sau khi lấy trị tuyệt đối. 

Bây giờ xét phân số $\displaystyle \frac{p}{q}$ với $\displaystyle p,q$ là hai số nguyên tố cùng nhau, $\displaystyle q >0$ và thỏa mãn $\displaystyle \Bigl| \alpha -\frac{p}{q}\Bigl| < \frac{1}{2q^{2}}$. Theo định nghĩa quy nạp của $\displaystyle q_{n}$ ta có $\displaystyle q_{n}  >0$ là các số nguyên dương và dãy $\displaystyle q_{n}$ đã cho là dãy tăng. Do đó luôn tồn tại một chỉ số $\displaystyle n$ sao cho $\displaystyle q_{n} \leqslant q< q_{n+1}$.

Giả sử rằng $\displaystyle |\alpha q-p|< |\alpha q_{n} -p_{n} |$ thì khi đó ta xét hệ phương trình tuyến tính 

$$
\begin{equation*}
\begin{cases}
q_{n} x+q_{n+1} y=q\\
p_{n} x+p_{n+1} y=p
\end{cases}
\end{equation*}
$$

Đây là hệ Cramer và có định thức của ma trận hệ số là $\displaystyle ( -1)^{n} \neq 0$ nên có nghiệm duy nhất $\displaystyle ( x_{0} ,y_{0})$. Ta sẽ chứng minh rằng $x_{0} ,y_{0}$ không thể bằng 0 . Nếu $x_{0} =0$, thì $q=q_{n+1} y_{0}$, điều này kéo theo $y_{0}  >0$. Do $y_{0} \in \mathbb{Z}$, ta phải có $y_{0} \geqslant 1$, từ đó ta có $q\geqslant q_{n+1}$ (mâu thuẫn với $q< q_{n+1})$. Nếu $y=0$ khi đó $p=x_{0} p_{n} ,q=y_{0} q_{n}$ và

$$
\begin{equation*}
|\alpha q-p|=| \alpha x_{0} q_{n} -x_{0} p_{n} =| x_{0}| | \alpha q_{n} -p_{n}| \geqslant | \alpha q_{n} -p_{n}| 
\end{equation*}
$$

(mâu thuẫn với giả thiết $|\alpha q-p|<|\alpha q_{n} -p_{n}|$). Tiếp theo ta sẽ chứng minh rằng $x_{0} ,y_{0}$ trái dấu nhau. Thật vậy, nếu $y_{0} < 0$ thì $x_{0} q_{n} =$ $q-y_{0} q_{n+1}  >0$ và điều này kéo theo $x_{0}  >0$. Nếu $y_{0}  >0$ thì do $q< q_{n+1}$ nên $q< y_{0} q_{n+1}$ và $x_{0} q_{n} =q-y_{0} q_{n+1} < 0$. Điều này kéo theo $x_{0} < 0$. Lại có $\alpha q_{n} -p_{n}$ và $\alpha q_{n+1} -p_{n+1}$ cũng trái dấu nhau (điều này là hệ quả của kết quả về tính đơn điệu của hai dãy chẵn lẻ ở trên), nên hai số $x_{0}( \alpha q_{n} -p_{n})$ và $y_{0}( \alpha q_{n+1} -p_{n+1})$ cùng dấu. Từ hệ phương trình định nghĩa $x_{0} ,y_{0}$ ta có

$$
\begin{equation*}
\alpha q-p=x_{0}( \alpha q_{n} -p_{n}) +y_{0}( \alpha q_{n+1} -p_{n+1})
\end{equation*}
$$


Do hai hạng tử có cùng dấu nên giá trị tuyệt đối của tổng hai hạng tử này sẽ bằng tổng giá trị tuyệt đối của từng hạng tử. Vì thế ta có:

$$
 \begin{array}{l}
|\alpha q-p|=|x_{0}( \alpha q_{n} -p_{n}) +y_{0}( \alpha q_{n+1} -p_{n+1}) |\\
=|x_{0}( \alpha q_{n} -p_{n}) |+|y_{0}( \alpha q_{n+1} -p_{n+1}) | >| x_{0}( \alpha q_{n} -p_{n})| \\
=| x_{0}| | ( \alpha q_{n} -p_{n})| \geqslant | \alpha q_{n} -p_{n}| 
\end{array}
$$

Điều này mâu thuẫn với giả thiết $|\alpha q-p|< | \alpha q_{n} -p_{n}|$. Vậy giả sử phía trên là sai, hay nói cách khác ta phải có

$$
\begin{equation*}
|\alpha q-p|\geqslant | \alpha q_{n} -p_{n}| .
\end{equation*}
$$

Sử dụng $\left| \alpha -\frac{p}{q}\right| < \frac{1}{2q^{2}}$, ta thu được

$$
\begin{equation*}
\left| \alpha -\frac{p_{n}}{q_{n}}\right| < \frac{1}{2qq_{n}} .
\end{equation*}
$$

Giả sử $p/q\neq p_{n} /q_{n}$ khi đó $qp_{n} -pq_{n}$ là một số nguyên khác không có giá trị tuyệt đối lớn hơn hoặc bằng 1 . Khi đó ta có

$$
\begin{equation*}
\frac{1}{qq_{n}} \leqslant \frac{| qq_{n} -pp_{n}| }{qq_{n}} =\left| \frac{p_{n}}{q_{n}} -\frac{p}{q}\right| \leqslant \left| \alpha -\frac{p_{n}}{q_{n}}\right| +\left| \alpha -\frac{p}{q}\right| < \frac{1}{2qq_{n}} +\frac{1}{2q^{2}}
\end{equation*}
$$

Bất đẳng thức vừa nhận được kéo theo $q< q_{n}$ (mâu thuẫn vởi già thiết $q\geqslant q_{n}$ ). Vậy $\displaystyle \frac{p}{q} =\frac{p_{n}}{q_{n}}$

Trong trường hợp $p/q$ không là phân số tối giản. Giả sử $p^{\prime } /q^{\prime }$ là phân số tối giản của nó khi đó $q >q^{\prime }  >0$ và

$$
\begin{equation*}
\left| \alpha -p^{\prime } /q^{\prime }\right| =|\alpha -p/q|< 1/\left( 2q^{2}\right) < 1/\left( 2q^{\prime 2}\right) .
\end{equation*}
$$

Áp dụng lập luận trên cho $p^{\prime } /q^{\prime }$ ta có $p^{\prime } /q^{\prime } =p_{n} /q_{n}$ với $n$ nào đó. Điều này kéo theo $p/q=p_{n} /q_{n}$.

Cuối cùng ta cần chứng minh rằng trong 3 phân số liên tiếp $\frac{p_{n}}{q_{n}}$,

$$
\begin{equation*}
\left| \alpha -\frac{p}{q}\right| < \frac{1}{\sqrt{5} q^{2}}
\end{equation*}
$$

Giả sử khẳng định là sai, nghĩa là cả 3 phân số liên tiếp này đều thoả mãn tính chất $\left| \alpha -\frac{p}{q}\right| \geqslant \frac{1}{\sqrt{5} q^{2}}$. Khi đó ta có

$$
\begin{equation*}
\left| \alpha -\frac{p_{n}}{q_{n}}\right| +\left| \alpha -\frac{p_{n+1}}{q_{n+1}}\right| \geqslant \frac{1}{\sqrt{5} q_{n}^{2}} +\frac{1}{\sqrt{5} q_{n+1}^{2}} .
\end{equation*}
$$

Ta biết rằng $\alpha$ nằm giữa $p_{n} /q_{n}$ và $p_{n+1} /q_{n+1}$ nên $p_{n} /q_{n} -\alpha$ và $\alpha -$ $p_{n+1} /q_{n+1}$ là cùng dấu. Vî thế ta có

$$
\begin{equation*}
\left| \alpha -\frac{p_{n}}{q_{n}}\right| +\left| \alpha -\frac{p_{n+1}}{q_{n+1}}\right| =\left| \frac{p_{n}}{q_{n}} -\frac{p_{n+1}}{q_{n+1}}\right| =\frac{1}{q_{n} q_{n+1}} .
\end{equation*}
$$

Kết hợp hai kết quả vừa nhận được ta có

$$
\begin{equation*}
\frac{q_{n}}{q_{n+1}} +\frac{q_{n+1}}{q_{n}} \leqslant \sqrt{5}
\end{equation*}
$$

(Do vế trái là một số vô tỉ nên bất đẳng thức trên không xảy ra dấu bằng.)

Chứng minh tương tự ta cũng có

$$
\begin{equation*}
\frac{q_{n+2}}{q_{n+1}} +\frac{q_{n+1}}{q_{n+2}} < \sqrt{5}
\end{equation*}
$$

Dặt $a=q_{n+1} /q_{n}$ và $b=q_{n+2} /q_{n+1}$. Khi đó $a^{-1} ,b$ là hai số dương thoả mãn bất đẳng thức

$$
\begin{equation*}
x+\frac{1}{x} < \sqrt{5} \Leftrightarrow x^{2} -\sqrt{5} x+1< 0
\end{equation*}
$$

Phương trình $x^{2} -\sqrt{5} x-1=0$ có 2 nghiệm phân biệt là $\phi =(1+\sqrt{5} )/2$ và $\overline{\phi } =(\sqrt{5} -1)/2$. Nên ta phải có $a^{-1}  >\overline{\phi }$ và $b< \phi$. Lại có từ định nghīa của $a,b$ ta có $b=a_{n+2} +a^{-1}$, nên ta có

$$
\begin{equation*}
\phi  >b=a_{n+2} +a^{-1} \geqslant 1+\overline{\phi } =\phi .
\end{equation*}
$$

Điều mâu thuẫn này chứng tỏ trong 3 phân số liên tiếp phải có một phân số thoả mãn tính chất của định lý.