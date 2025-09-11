from Crypto.PublicKey import RSA
from Crypto.Util.number import * 
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from os import urandom
# plain RSA
def keygen(nbits):
    p = getPrime(nbits)
    q = getPrime(nbits)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = pow(e, -1 ,phi)
    pubkey  = [e,n]
    privkey = [d,n]
    return pubkey, privkey
def encrypt(m,pubkey):
    if pubkey == []:
        return KeyError
    e,n = pubkey
    return pow(m, e, n)
def decrypt(c,privkey):
    if privkey == []:
        return KeyError
    d, n = privkey
    return pow(c, d, n)
# n = 512
# pub, priv = keygen(n)
# m = urandom(24)
# plain_m = bytes_to_long(m)
# c = encrypt(plain_m,pub)
# m_ = long_to_bytes(decrypt(c,priv))
# assert m == m_

# PKCS v1.5
def keygenPKCS(nbits):
    key = RSA.generate(nbits)
    return key.publickey(), key 
def encryptPKCS(message, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(message)
def decryptPKCS(ciphertext, privkey):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext)
pub, priv = keygenPKCS(1024)
m = urandom(32)
c = encryptPKCS(m,pub)
m_ = decryptPKCS(c,priv)
assert m == m_
print(m_)