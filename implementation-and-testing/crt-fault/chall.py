#!/usr/bin/env python3
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from math import gcd


def gen_rsa_crt(bits: int = 2048):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    d = inverse(e, phi)

    dP = d % (p - 1)
    dQ = d % (q - 1)
    qInv = inverse(q, p)

    return {
        "p": p,
        "q": q,
        "n": n,
        "e": e,
        "d": d,
        "dP": dP,
        "dQ": dQ,
        "qInv": qInv,
    }


def sign_crt_correct(m: int, key: dict) -> int:
    p, q = key["p"], key["q"]
    dP, dQ, qInv = key["dP"], key["dQ"], key["qInv"]
    n = key["n"]

    s1 = pow(m, dP, p)
    s2 = pow(m, dQ, q)

    h = (qInv * (s1 - s2)) % p
    s = (s2 + h * q) % n
    return s


def sign_crt_faulty(m: int, key: dict) -> int:
    p, q = key["p"], key["q"]
    dP, dQ, qInv = key["dP"], key["dQ"], key["qInv"]
    n = key["n"]

    s1 = pow(m, dP, p)
    s2 = (pow(m, dQ, q) + 1) % q  # injected fault

    h = (qInv * (s1 - s2)) % p
    s_faulty = (s2 + h * q) % n
    return s_faulty


def recover_factors_from_faulty_signature(n: int, e: int, m: int, s_faulty: int):
    diff = pow(s_faulty, e, n) - m
    p_rec = gcd(diff, n)
    if p_rec in (1, n):
        raise ValueError("Attack failed")
    q_rec = n // p_rec
    return p_rec, q_rec


msg = "crypto{fake_flag}"
m = bytes_to_long(msg.encode())

key = gen_rsa_crt(bits=256)
n, e = key["n"], key["e"]

s_good = sign_crt_correct(m, key)
assert pow(s_good, e, n) == m

s_faulty = sign_crt_faulty(m, key)

print(f"n = {n}")
print(f"e = {e}")
print(f"m = {m}")
print(f"faulty signature = {s_faulty}")
