# RSA-Based-Cryptography
Students: 
- Lê Trí Đức - 24520009
- Phạm Nguyễn Thành Long - 24521011

Lecturer: Nguyễn Ngọc Tự

# Overview
- Scenario: Secure service company uses RSA-based algorithms for securing transactions and digital signatures. They want to ensure the robustness of their RSA implementation against potential attacks. 
- Gaps: While RSA is a widely accepted and used in public-key cryptosystem, improper implementations or usage of weak parameters can lead to vulnerabilities.
- Motivations: To ensure the integrity and confidentiality of financial transactions and to maintain the trust of clients and stakeholders. 

# Mathematical Background  

## Encryption and Signature Schemes

In this project we focus on **RSA-based encryption** and **RSA-based digital signatures**, with an emphasis on two signature variants: **PKCS#1 v1.5** and **RSASSA-PSS**.

### 1. RSA Encryption

An RSA key pair is generated as follows:

- Choose two large primes $p, q$ and compute the modulus $N = p q$.
- Compute $\varphi(N) = (p-1)(q-1)$.
- Choose a public exponent $e$ such that $\gcd(e, \varphi(N)) = 1$.
- Compute the private exponent $d$ such that
  $$
  e \cdot d \equiv 1 \pmod{\varphi(N)}.
  $$

In short:

- **Public key:** $(N, e)$  
- **Private key:** $(N, d)$



#### Textbook RSA (basic but insecure)

The “textbook” RSA operations are:

- **Encryption:**  $c = m^e \bmod N$
  
- **Decryption:** 
  $m = c^d \bmod N$

Here $m$ is an integer encoding of the plaintext with $0 \le m < N$.

Textbook RSA is **not secure in practice** because:

- It is **deterministic** (encrypting the same message always gives the same ciphertext).
- It does **not** provide semantic security, and is vulnerable to chosen-plaintext and chosen-ciphertext attacks.

Real-world systems therefore never use textbook RSA; they always wrap it with a padding/encoding scheme.



#### CRT Optimization (speeding up decryption/signing)

Computing $c^d \bmod N$ directly is expensive when $N$ is large. Most implementations speed this up using the Chinese Remainder Theorem (CRT), by precomputing:

- $d_p = d \bmod (p-1)$  
- $d_q = d \bmod (q-1)$  
- $u = q^{-1} \bmod p$  (the modular inverse of $q$ modulo $p$)

- **Encryption CRT:** Same as textbook RSA


- **Decryption CRT:**

1. $\displaystyle m_{p} \equiv c^{d_{p}} \ (\bmod p) ,\ m_{q} \ \equiv c^{d_{q}} \ (\bmod q)$

2. $\displaystyle h\equiv ( m_{p} -m_{q}) u\ (\bmod p)$

3. $\displaystyle m\equiv m_{q} +q\cdotp h( \ \bmod n)$

4. Output $\displaystyle m$



### 2. RSA Signature Schemes

RSA signatures use the same key pair $(N, e)$, $(N, d)$ but **reverse the roles** of encryption and decryption:

- Signing (with the private key): $s = m^d \bmod N$
- Verification (with the public key): check $m \stackrel{?}{=} s^e \bmod N$

In practice, $m$ is not the raw message but a padded/hash-encoded value.  
Different signature schemes define different ways to **encode the hash** of a message before applying RSA.

We focus on two main signature schemes:

#### 2.1. RSA Signatures with PKCS#1 v1.5 (RSASSA-PKCS1-v1_5)

PKCS#1 v1.5 has long been the most widely deployed RSA signature scheme in practice. The original definition of the RSASSA-PKCS1-v1_5 algorithm is given in RFC 3447, available at [https://datatracker.ietf.org/doc/html/rfc3447](https://datatracker.ietf.org/doc/html/rfc3447).

High-level idea:

1. Given a message $M$, compute its hash $H = \text{Hash}(M)$ (e.g., SHA-256).
2. Build an encoded message (EM) of the form:
   - `0x00 || 0x01 || 0xFF ... FF || 0x00 || T`
   - where `T` is an ASN.1/DER encoding of the hash algorithm identifier and the hash value $H$.
3. Interpret EM as an integer $m_{\text{EM}}$ and compute the signature:
   - $s = m_{\text{EM}}^d \bmod N$.
4. Verification recomputes EM from the message and checks:
   - $s^e \bmod N$ equals the expected EM.

**Properties:**

- Deterministic: signing the same message twice yields the same signature.
- Very widely supported (TLS, X.509 certificates, code signing, JWT RS256 in some libraries, etc.).
- Known to be **fragile** if verification is not implemented strictly:
  - Lenient parsing, acceptance of malformed paddings, or incorrect handling of the ASN.1 structure can lead to signature forgery attacks.
  - Because of its structured deterministic padding, it is harder to prove security in a tight theoretical sense.


#### 2.2. RSA Signatures with PSS (RSASSA-PSS)

RSASSA-PSS (Probabilistic Signature Scheme) is a newer RSA signature scheme designed with **provable security** in mind.

High-level idea:

1. Given a message $M$, compute $H = \text{Hash}(M)$.
2. Generate a random salt and build an encoded message (EM) using a randomized padding construction:
   - EM combines $H$, the salt, and some fixed bits via a mask generation function (MGF).
3. Interpret EM as an integer $m_{\text{EM}}$ and compute:
   - $s = m_{\text{EM}}^d \bmod N$.
4. Verification recomputes EM (including deriving/checking the salt structure) and checks:
   - $s^e \bmod N$ equals the expected EM.

**Properties:**

- **Probabilistic:** signing the same message multiple times produces **different signatures** thanks to the random salt.
- Comes with strong theoretical guarantees: under standard assumptions (e.g., hardness of RSA and properties of the hash/MGF), RSASSA-PSS can be proven secure against adaptive chosen-message attacks.
- Recommended by modern standards for new applications:
  - Often preferred over PKCS#1 v1.5 in new protocols and certificate profiles.

In this project, PSS plays the role of a **“modern, more robust”** signature scheme that we can compare against PKCS#1 v1.5 in terms of:

- Security guarantees,
- Resistance to subtle parsing bugs,
- Deployment challenges (library support, compatibility with existing systems).

---

### 3. Summary (RSA Encryption vs Signatures, PKCS#1 v1.5 vs PSS)

- RSA defines a core mathematical primitive using $(N, e, d)$; **encryption** and **signatures** are different modes built on top.
- Real-world security critically depends on **padding and encoding schemes**, not just on the hardness of factoring $N$.
- **PKCS#1 v1.5 signatures**:
  - Deterministic, widely deployed.
  - Sensitive to implementation bugs and lenient parsing.
- **RSASSA-PSS**:
  - Randomized, with stronger theoretical security.
  - Recommended as the preferred scheme for new designs and migrations.

These schemes and their differences are central to our later sections on **attack experiments (Bleichenbacher, timing, fault attacks)** and on **deployment weakness analysis**.



## Factoring Problem in RSA

### 1. Context

In our setting, a trusted key-generation algorithm $\text{GenModulus}(1^n)$ outputs a triple $(N, p, q)$, where $p$ and $q$ are random $n$-bit primes and $N = pq$.

The RSA public key contains $N$ (and a public exponent $e$), while the prime factors $p$ and $q$ are kept secret and form part of the private key.

In practice, this modulus $N$ is embedded in:

- Server certificates used in TLS connections (e.g., for online payments or secure APIs),
- Digital-signature keys used to sign transactions, contracts, or software updates,
- Possibly hardware tokens / HSMs used by the service provider.

An external adversary $\mathcal{A}$ can freely observe $N$ (it is public by design) and may obtain many ciphertexts or signatures under this modulus.  
The most direct way for $\mathcal{A}$ to break RSA is therefore to **solve the factoring problem** for $N$: find $p, q > 1$ such that $N = pq$.

The **factoring assumption** states that, for moduli generated by $\text{GenModulus}$, no efficient (polynomial-time) adversary can factor $N$ with non-negligible probability in $n$.

### 2. Risks

If the factoring assumption fails for our generated moduli, the consequences for the system are severe:

- **Private-key recovery:**  
  Once $\mathcal{A}$ computes $p$ and $q$, it can derive $\varphi(N)$ and recover the private exponent $d$.  
  At this point the adversary has a full copy of the RSA private key.

- **Loss of confidentiality:**  
  The attacker can decrypt any ciphertext encrypted under the public key $(N, e)$.  
  This includes past recorded traffic (if stored), leading to retrospective disclosure of sensitive data such as credentials, financial information, or session keys.

- **Loss of integrity, authenticity, and non-repudiation:**  
  With the private key, the adversary can forge valid RSA signatures that are indistinguishable from signatures produced by the legitimate key owner.  
  This enables impersonation of servers, forging of transaction approvals, or signing of malicious software updates.

- **System-wide impact if keys are re-used:**  
  In many real deployments, the same RSA key pair is used across multiple services (e.g., web server, VPN, code signing).  
  Factoring a single modulus $N$ may compromise multiple independent security functions at once.

In short, **breaking the factoring assumption directly breaks the security of any RSA-based encryption or signature scheme built on that modulus**.

### 3. Security Goals

To rely on RSA securely, the system’s design must ensure that the factoring assumption is realistic for all deployed moduli:

- **Goal 1 – Hard-to-factor moduli (sufficient key sizes):**  
  Choose modulus sizes $N$ large enough that the best known classical factoring algorithms (e.g., Number Field Sieve) remain computationally infeasible in practice.  
  For current deployments, this typically means at least 2048-bit moduli, and moving to 3072-bit or higher for long-term security.

- **Goal 2 – High-quality modulus generation:**  
  Ensure $\text{GenModulus}$ uses cryptographically secure randomness to generate $p$ and $q$:  
  - primes of appropriate size,  
  - not too close to each other,  
  - not taken from small or structured sets.  
  This avoids “weak RSA keys” that might be factored using specialized attacks (e.g., shared-prime or low-entropy key attacks).

- **Goal 3 – Key isolation and minimal reuse:**  
  Avoid using the same modulus $N$ for many independent security domains (e.g., mixing TLS, code signing, and document signing with one key).  
  Even if one modulus were factored, the blast radius should be limited.

- **Goal 4 – Forward-looking protection against advances in factoring:**  
  Monitor cryptanalytic progress and adjust key sizes and lifetimes accordingly.  
  Plan for migration away from factoring-based schemes (e.g., toward post-quantum cryptography) in anticipation of quantum attacks (such as Shor’s algorithm) that would make factoring easy.

These goals collectively formalize what it means, at the system level, to “assume factoring is hard”: we must choose parameters, algorithms, and operational practices so that any realistic adversary’s success probability in factoring $N$ (as produced by $\text{GenModulus}$) remains negligible.


# Proposed Solution

## Cryptanalysis Tools
- Python 3.x

Install: https://www.python.org/downloads/
- Sagemath

See the installation guide here: https://doc.sagemath.org/html/en/installation/index.html. For the sake of convenience, it should be installed using conda-forge.

After installing, activate it with the following command:
```
duccorp@DESKTOP-RH0V9GH:~/RSA-Based-Cryptography$ source ~/miniforge3/bin/activate
(base) duccorp@DESKTOP-RH0V9GH:~/RSA-Based-Cryptography$ conda activate sage
(sage) duccorp@DESKTOP-RH0V9GH:~/RSA-Based-Cryptography$ sage
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 10.6, Release Date: 2025-03-31                    │
│ Using Python 3.11.13. Type "help()" for help.                      │
└────────────────────────────────────────────────────────────────────┘
sage:
```

You can check your SageMath version by 
```
(sage) duccorp@DESKTOP-RH0V9GH:~/RSA-Based-Cryptography$ sage --version
SageMath version 10.6, Release Date: 2025-03-31
```
In Visual Studio Code, press `Ctrl+Shift+P` and choose the correct Python interpreter before coding. 

<img width="746" height="89" alt="{034810DA-A092-4093-81BE-1FA88BCB7E2F}" src="https://github.com/user-attachments/assets/c65b8d6f-22d3-4503-88b9-9daa00dbe653" />

Import it with 
```python
from sage.all import * 
```
- Pycryptodome

Docs and installation guide of the library: https://pycryptodome.readthedocs.io/en/latest/src/introduction.html. PyCryptodome provides many cryptographic functions for working with RSA

## Basic attack models

We will focus on some specific cases where the RSA parameters do not satisfy the security conditions assumed by the `GenModulus` algorithm in the factoring assumption. These “non-ideal” choices produce **vulnerable instances** that are easier to analyze and attack.


### Factoring Attacks



### Wiener's Attacks

Wiener's attack is an attack on RSA that uses continued fractions to find the private exponent when it is small. Specifically when it is less than $\displaystyle \frac{1}{3}\sqrt[4]{n}$ where $\displaystyle n$ is the modulus.



Wiener's attack is based on the following theorem:
#### Wiener's theorem

Let $\displaystyle n=pq$ with $\displaystyle q< p< 2q$. Let $\displaystyle d< \frac{1}{3}\sqrt[4]{n}$. Given $\displaystyle n$ and $\displaystyle e$ with $\displaystyle ed\equiv 1\ \bmod \phi ( n)$, the attacker can efficiently recover $\displaystyle d$. 

#### Attack 


Suppose we have the public key $(n, e)$, this attack will determine $d$.

1. Convert the fraction $\dfrac{e}{n}$ into a continued fraction

$$
\frac{e}{n} = [a_0; a_1, a_2, \dots, a_{k-2}, a_{k-1}, a_k].
$$

3. Iterate over each convergent of this continued fraction:
 
 
$$
\frac{a_0}{1},\quad
a_0 + \frac{1}{a_1},\quad
a_0 + \frac{1}{a_1 + \frac{1}{a_2}},\quad
\dots,\quad
a_0 + \frac{1}{a_1 + \frac{1}{\ddots + \frac{1}{a_{k-2} + \frac{1}{a_{k-1}}}}}.
$$

4. For each convergent, say $\dfrac{k}{d}$, check if it can be the correct one by doing:

   - Set the numerator to be $k$ and the denominator to be $d$.
   - Check if $d$ is odd; if not, move on to the next convergent.
   - Check if $ed \equiv 1 \pmod{k}$; if not, move on to the next convergent.
   - Set $\varphi(n) = \frac{ed - 1}{k}$ and find the roots of the polynomial $x^2 - (n - \varphi(n) + 1)x + n.$
   - If the roots are integers, then we have found $d$ (otherwise, move on to the next convergent).

5. If all convergents have been tried and none of them work, then the given RSA parameters are not vulnerable to Wiener's attack.


### Low‑exponent attacks



### Fault attacks on RSA‑CRT



# References
- [Twenty Years of Attacks on the RSA Cryptosystem, Dan Boneh](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)
- [Introduction to Modern Cryptography, Second Edition](https://eclass.uniwa.gr/modules/document/file.php/CSCYB105/Reading%20Material/%5BJonathan_Katz%2C_Yehuda_Lindell%5D_Introduction_to_Mo%282nd%29.pdf)
- [Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1](https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)
- [Modulus Fault Attacks Against RSA-CRT Signatures](https://eprint.iacr.org/2011/388.pdf)
- [New Partial Key Exposure Attacks on RSA](https://www.iacr.org/archive/crypto2003/27290027/27290027.pdf)
- [Small Public Exponent Brings More: Improved Partial Key Exposure Attacks against RSA](https://eprint.iacr.org/2024/1329.pdf)
- [Cache-Timing Attacks on RSA Key Generation](https://d-nb.info/1205895671/34)
- [Timing Attacks on Software Implementation of RSA](https://ir.library.oregonstate.edu/downloads/fn106z04s)
- [On the Security of the PKCS#1 v1.5 Signature Scheme](https://eprint.iacr.org/2018/855.pdf)
