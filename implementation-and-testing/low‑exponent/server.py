from Crypto.Util.number import bytes_to_long, getPrime
import os


def RSA_encrypt(message):
    m = bytes_to_long(message)
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 30
    c = pow(m, e, N)
    return N, e, c
m = b'Secret message for RSA encryption'
M = bytes_to_long(m)

while True: 
    opt = int(input("Choose an option:\n1. Get RSA encryption of the message\n2. Exit\n"))
    if opt == 2:
        break 
    else: 
        N, e, c = RSA_encrypt(m)
        print(f'N = {N}')
        print(f'c = {c}')
