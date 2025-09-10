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



# References
- [Twenty Years of Attacks on the RSA Cryptosystem, Dan Boneh](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)
- [Introduction to Modern Cryptography, Second Edition](https://eclass.uniwa.gr/modules/document/file.php/CSCYB105/Reading%20Material/%5BJonathan_Katz%2C_Yehuda_Lindell%5D_Introduction_to_Mo%282nd%29.pdf)
