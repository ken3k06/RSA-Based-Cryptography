from sage.all import * 
import sys
from pwn import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
import random
import time
p = getPrime(1024)
q = getPrime(1024)
n = p*q 

P = PolynomialRing(Zmod(n), name = 'x')
x = P.gen()

def HGCD(a, b):
    if 2 * b.degree() <= a.degree() or a.degree() == 1:
        return 1, 0, 0, 1
    m = a.degree() // 2
    a_top, a_bot = a.quo_rem(x**m)
    b_top, b_bot = b.quo_rem(x**m)
    R00, R01, R10, R11 = HGCD(a_top, b_top)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    q, e = c.quo_rem(d)
    d_top, d_bot = d.quo_rem(x**(m // 2))
    e_top, e_bot = e.quo_rem(x**(m // 2))
    S00, S01, S10, S11 = HGCD(d_top, e_top)
    RET00 = S01 * R00 + (S00 - q * S01) * R10
    RET01 = S01 * R01 + (S00 - q * S01) * R11
    RET10 = S11 * R00 + (S10 - q * S11) * R10
    RET11 = S11 * R01 + (S10 - q * S11) * R11
    return RET00, RET01, RET10, RET11
    
def GCD(a, b):
    print(a.degree(), b.degree())
    q, r = a.quo_rem(b)
    if r == 0:
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == 0:
        return c.monic()
    q, r = c.quo_rem(d)
    if r == 0:
        return d
    return GCD(d, r)
m = b'Secret message to attack the challenge'
M = bytes_to_long(m)
es = [3,37, 53, 46769, 65537]
for e in es: 
    a = random.randint(2,n-1)
    b = random.randint(2,n-1)
    pad_msg = (a * M + b) % n
    c_pad = pow(pad_msg, e, n)
    c = pow(M,e,n)
    f = x**e - c 
    g = (a*x+b)**e - c_pad 
    start = time.time()
    h = GCD(f,g).monic()
    if h.degree() == 1: 
        root = -h.coefficients()[0]
        end = time.time()
        print(f"Recovered in {end - start} seconds")
        print(f"recovered message for e={e}: ", long_to_bytes(int(root)))
    else:
        continue 



    
