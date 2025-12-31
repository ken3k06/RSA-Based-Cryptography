import argparse
import sys
import os
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256

class RSAEngine:
    def __init__(self, key_path=None, password=None):
        self.key = None
        if key_path:
            with open(key_path, 'rb') as f:
                self.key = RSA.import_key(f.read(), passphrase=password)
        
    def generate(self, nbits=2048):
        self.key = RSA.generate(nbits)

    def save_keys(self, out_dir, password=None):
        if not self.key:
            raise ValueError("No key loaded")
        
        priv_key = self.key.export_key(pkcs=8, protection="scryptAndAES128-CBC", passphrase=password) if password else self.key.export_key()
        with open(os.path.join(out_dir, "private.pem"), "wb") as f:
            f.write(priv_key)

        pub_key = self.key.publickey().export_key()
        with open(os.path.join(out_dir, "public.pem"), "wb") as f:
            f.write(pub_key)

    def encrypt_oaep(self, msg):
        cipher = PKCS1_OAEP.new(self.key.publickey(), hashAlgo=SHA256)
        return cipher.encrypt(msg)

    def decrypt_oaep(self, ct):
        cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)
        return cipher.decrypt(ct)

    def raw_encrypt(self, msg):
        m = bytes_to_long(msg)
        n = self.key.n
        e = self.key.e
        return long_to_bytes(pow(m, e, n))

    def raw_decrypt(self, ct):
        c = bytes_to_long(ct)
        n = self.key.n
        d = self.key.d
        p = self.key.p
        q = self.key.q
        u = self.key.u 
        
        if c >= n:
            raise ValueError("Ciphertext > modulus")

        d_p = d % (p - 1)
        d_q = d % (q - 1)
        m_p = pow(c, d_p, p)
        m_q = pow(c, d_q, q)
        h = ((m_q - m_p) * u) % q
        m = (m_p + p * h) % n
        return long_to_bytes(m)

    def sign_pkcs1_v1_5(self, msg):
        h = SHA256.new(msg)
        signer = pkcs1_15.new(self.key)
        return signer.sign(h)

    def verify_pkcs1_v1_5(self, msg, signature):
        h = SHA256.new(msg)
        try:
            pkcs1_15.new(self.key.publickey()).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def sign_pkcs1_pss(self, msg):
        h = SHA256.new(msg)
        signer = pss.new(self.key)
        return signer.sign(h)

    def verify_pkcs1_pss(self, msg, signature):
        h = SHA256.new(msg)
        try:
            pss.new(self.key.publickey()).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

def main():
    parser = argparse.ArgumentParser(
    description="RSA command-line tool based on PyCryptodome",
    formatter_class=argparse.RawTextHelpFormatter,
    epilog="""Examples:
  python3 rsa_cli.py keygen -b 2048
  python3 rsa_cli.py enc -i msg.txt -o ct.bin
  python3 rsa_cli.py dec -i ct.bin -o pt.txt
  python3 rsa_cli.py sign --scheme pss -i msg.txt -o sig.bin
  python3 rsa_cli.py verify --scheme pss -i msg.txt -s sig.bin
"""
)
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen_parser = subparsers.add_parser("keygen", help="Generate RSA Keypair")
    gen_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size (default: 2048)")
    gen_parser.add_argument("-o", "--out", type=str, default=".", help="Output directory")
    gen_parser.add_argument("--pass", dest="password", type=str, help="Password for private key")

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt data")
    enc_parser.add_argument("-k", "--key", required=True, help="Public key path")
    enc_parser.add_argument("-in", "--input", required=True, help="Input file")
    enc_parser.add_argument("-out", "--output", required=True, help="Output file")
    enc_parser.add_argument("--raw", action="store_true", help="Use Raw RSA (Textbook) instead of OAEP")

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt data")
    dec_parser.add_argument("-k", "--key", required=True, help="Private key path")
    dec_parser.add_argument("-in", "--input", required=True, help="Input file")
    dec_parser.add_argument("-out", "--output", required=True, help="Output file")
    dec_parser.add_argument("--pass", dest="password", type=str, help="Password for private key")
    dec_parser.add_argument("--raw", action="store_true", help="Use Raw RSA (Textbook) instead of OAEP")

    sign_parser = subparsers.add_parser("sign", help="Sign data")
    sign_parser.add_argument("-k", "--key", required=True, help="Private key path")
    sign_parser.add_argument("-in", "--input", required=True, help="Input file")
    sign_parser.add_argument("-out", "--output", required=True, help="Output signature file")
    sign_parser.add_argument("--legacy", action="store_true", help="Use PKCS#1 v1.5 instead of PSS")

    ver_parser = subparsers.add_parser("verify", help="Verify signature")
    ver_parser.add_argument("-k", "--key", required=True, help="Public key path")
    ver_parser.add_argument("-in", "--input", required=True, help="Data file")
    ver_parser.add_argument("-sig", "--signature", required=True, help="Signature file")
    ver_parser.add_argument("--legacy", action="store_true", help="Use PKCS#1 v1.5 instead of PSS")

    args = parser.parse_args()

    try:
        if args.command == "keygen":
            engine = RSAEngine()
            print(f"[*] Generating {args.bits}-bit RSA keypair...")
            engine.generate(args.bits)
            engine.save_keys(args.out, args.password)
            print(f"[+] Keys saved to {args.out}/private.pem and {args.out}/public.pem")

        elif args.command == "encrypt":
            engine = RSAEngine(args.key)
            with open(args.input, 'rb') as f:
                data = f.read()
            
            if args.raw:
                ct = engine.raw_encrypt(data)
                mode = "RAW"
            else:
                ct = engine.encrypt_oaep(data)
                mode = "OAEP"
            
            with open(args.output, 'wb') as f:
                f.write(ct)
            print(f"[+] Encrypted ({mode}) data saved to {args.output}")

        elif args.command == "decrypt":
            engine = RSAEngine(args.key, args.password)
            with open(args.input, 'rb') as f:
                ct = f.read()
            
            if args.raw:
                pt = engine.raw_decrypt(ct)
                mode = "RAW"
            else:
                pt = engine.decrypt_oaep(ct)
                mode = "OAEP"
            
            with open(args.output, 'wb') as f:
                f.write(pt)
            print(f"[+] Decrypted ({mode}) data saved to {args.output}")

        elif args.command == "sign":
            engine = RSAEngine(args.key)
            with open(args.input, 'rb') as f:
                data = f.read()
            
            if args.legacy:
                sig = engine.sign_pkcs1_v1_5(data)
                mode = "PKCS#1 v1.5"
            else:
                sig = engine.sign_pkcs1_pss(data)
                mode = "PSS"
                
            with open(args.output, 'wb') as f:
                f.write(sig)
            print(f"[+] Signed ({mode}) signature saved to {args.output}")

        elif args.command == "verify":
            engine = RSAEngine(args.key)
            with open(args.input, 'rb') as f:
                data = f.read()
            with open(args.signature, 'rb') as f:
                sig = f.read()

            if args.legacy:
                valid = engine.verify_pkcs1_v1_5(data, sig)
                mode = "PKCS#1 v1.5"
            else:
                valid = engine.verify_pkcs1_pss(data, sig)
                mode = "PSS"
            
            if valid:
                print(f"[+] Signature ({mode}) is VALID")
            else:
                print(f"[-] Signature ({mode}) is INVALID")
                sys.exit(1)

    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
