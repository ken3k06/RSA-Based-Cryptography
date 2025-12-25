import argparse
import subprocess
import sys

def run(cmd):
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode())
    return p.stdout

def keygen(bits, priv, pub):
    run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-pkeyopt", f"rsa_keygen_bits:{bits}",
        "-out", priv
    ])
    run([
        "openssl", "pkey",
        "-in", priv,
        "-pubout",
        "-out", pub
    ])

def encrypt_oaep(pub, infile, outfile):
    run([
        "openssl", "pkeyutl",
        "-encrypt",
        "-pubin",
        "-inkey", pub,
        "-in", infile,
        "-out", outfile,
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256"
    ])

def decrypt_oaep(priv, infile, outfile):
    run([
        "openssl", "pkeyutl",
        "-decrypt",
        "-inkey", priv,
        "-in", infile,
        "-out", outfile,
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256"
    ])

def sign(priv, scheme, infile, sigfile):
    cmd = [
        "openssl", "dgst",
        "-sha256",
        "-sign", priv,
        "-out", sigfile
    ]
    if scheme == "pss":
        cmd += [
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:-1"
        ]
    cmd.append(infile)
    run(cmd)

def verify(pub, scheme, infile, sigfile):
    cmd = [
        "openssl", "dgst",
        "-sha256",
        "-verify", pub,
        "-signature", sigfile
    ]
    if scheme == "pss":
        cmd += [
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:-1"
        ]
    cmd.append(infile)
    try:
        run(cmd)
        print("VALID")
    except RuntimeError:
        print("INVALID")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen")
    p.add_argument("-b", "--bits", type=int, default=2048)
    p.add_argument("--priv", default="priv.pem")
    p.add_argument("--pub", default="pub.pem")

    p = sub.add_parser("enc")
    p.add_argument("--pub", default="pub.pem")
    p.add_argument("-i", "--infile", required=True)
    p.add_argument("-o", "--outfile", default="cipher.bin")

    p = sub.add_parser("dec")
    p.add_argument("--priv", default="priv.pem")
    p.add_argument("-i", "--infile", required=True)
    p.add_argument("-o", "--outfile", default="plain.bin")

    p = sub.add_parser("sign")
    p.add_argument("--scheme", choices=["v15", "pss"], default="pss")
    p.add_argument("--priv", default="priv.pem")
    p.add_argument("-i", "--infile", required=True)
    p.add_argument("-o", "--sig", default="sig.bin")

    p = sub.add_parser("verify")
    p.add_argument("--scheme", choices=["v15", "pss"], default="pss")
    p.add_argument("--pub", default="pub.pem")
    p.add_argument("-i", "--infile", required=True)
    p.add_argument("-s", "--sig", required=True)

    args = parser.parse_args()

    if args.cmd == "keygen":
        keygen(args.bits, args.priv, args.pub)

    elif args.cmd == "enc":
        encrypt_oaep(args.pub, args.infile, args.outfile)

    elif args.cmd == "dec":
        decrypt_oaep(args.priv, args.infile, args.outfile)

    elif args.cmd == "sign":
        sign(args.priv, args.scheme, args.infile, args.sig)

    elif args.cmd == "verify":
        verify(args.pub, args.scheme, args.infile, args.sig)

if __name__ == "__main__":
    main()
