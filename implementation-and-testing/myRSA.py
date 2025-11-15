from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes, random

class myRSA: 
    def __init__(self, nbits): # nbits : security parameter 
        assert nbits >= 1024, "Not enough security level"
        self.key = RSA.generate(nbits)
        self.n = self.key.n 
        self.p = self.key.p 
        self.q = self.key.q 
        self.e = self.key.e 
        self.d = self.key.d
        self.u = getattr(self.key, "u", None) # u = p^-1 mod q for CRT 
    def encrypt_oaep(self, msg:bytes) -> bytes: 
        pub = self.key.publickey()
        cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
        return cipher.encrypt(msg)
    def decrypt_oaep(self, ct:bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)
        return cipher.decrypt(ct)
    def raw_encrypt(self, msg:bytes) -> bytes:
        m = bytes_to_long(msg)
        return long_to_bytes(pow(m, self.e, self.n))
    def raw_decrypt(self, ct:bytes) -> bytes: 
        c = bytes_to_long(ct)
        if c>=self.n:
            raise ValueError("Ciphertext > modulus")
        n = self.n 
        d = self.d 
        p = self.p 
        q = self.q 
        u = self.u 
        d_p = d % (p-1)
        d_q = d % (q-1)
        m_p = pow(c, d_p, p)
        m_q = pow(c, d_q, q)
        h = ((m_q - m_p) * u) % q
        m = (m_p + p * h) % n
        return long_to_bytes(m)

    def sign_pkcs1_v1_5(self, msg:bytes) -> bytes:
        h = SHA256.new(msg)
        signer = pkcs1_15.new(self.key)
        return signer.sign(h)
    def verify_pkcs1_v1_5(self, msg:bytes, signature:bytes) -> bool:
        h = SHA256.new(msg)
        try: 
            pkcs1_15.new(self.key.publickey()).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False 
    
    def sign_pkcs1_pss(self, msg:bytes) -> bytes: 
        h = SHA256.new(msg)
        signer = pss.new(self.key)
        return signer.sign(h)
    def verify_pkcs1_pss(self, msg:bytes, signature:bytes) -> bool:
        h = SHA256.new(msg)
        try: 
            pss.new(self.key.publickey()).verify(h,signature)
            return True 
        except (ValueError, TypeError):
            return False 
if __name__ == "__main__":
    rsa = myRSA(4096)
    msg = b'Crypto{fake_flag_for_testing}'
    c_oaep = rsa.encrypt_oaep(msg)
    msg_oaep = rsa.decrypt_oaep(c_oaep)
    assert msg_oaep == msg # true 
    c_raw = rsa.raw_encrypt(msg)
    m_raw = rsa.raw_decrypt(c_raw)
    assert m_raw == msg 
    sign_v15 = rsa.sign_pkcs1_v1_5(msg)
    verify_pkcs = rsa.verify_pkcs1_v1_5(msg,sign_v15)
    assert verify_pkcs == True
    sign_pss = rsa.sign_pkcs1_pss(msg)
    verify_pss = rsa.verify_pkcs1_pss(msg, sign_pss)
    assert verify_pss == True
    print("All test passed!")
    
