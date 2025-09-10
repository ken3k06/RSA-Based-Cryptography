# RSA-Based-Cryptography
Students: 
- Lê Trí Đức - 24520009
- Phạm Nguyễn Thành Long - 2452....

Lecturer: Nguyễn Ngọc Tự

# Overview
- Scenario: Secure service company uses RSA-based algorithms for securing transactions and digital signatures. They want to ensure the robustness of their RSA implementation against potential attacks. 
- Gaps: While RSA is a widely accepted and used in public-key cryptosystem, improper implementations or usage of weak parameters can lead to vulnerabilities.
- Motivations: To ensure the integrity and confidentiality of financial transactions and to maintain the trust of clients and stakeholders. 

# Mathematical Background
## Factoring problem
We begin with a discussion of one of the oldest problems: integer factorization or factoring. 

**Problem**: Given a composite integer $N$, the factoring problem is to find integers $p,q > 1$ such that

$$pq = N$$

Factoring large integers is considered difficult and the security of the RSA cryptosystem is fundamentally based on the hardness of this problem. 
## The Factoring Assumtion

Let $\text{GenModulus}$ be a polynomial-time algorithm that, on input $1^n$, outputs $(N,p,q)$ where $N=pq$ and $p$ and $q$ are two $n$-bit primes except with probability negligible in $n$.  Then we consider the following experiment for a given algorithm $\mathcal{A}$ and parameter $n$: 

# Implementation and Testing
- Python 3.x
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

```
# References
- [Twenty Years of Attacks on the RSA Cryptosystem, Dan Boneh](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)
- [Introduction to Modern Cryptography, Second Edition](https://eclass.uniwa.gr/modules/document/file.php/CSCYB105/Reading%20Material/%5BJonathan_Katz%2C_Yehuda_Lindell%5D_Introduction_to_Mo%282nd%29.pdf)
