#!/usr/bin/env python3
"""
Kocher-style timing attack demo (single-file local measurement).

- Self-contained: Miller-Rabin prime gen, RSA keygen, timing modexp, attack analysis.
- Demonstrates AMP=1 vs AMP=50 behavior.
- Saves report to /mnt/data/kocher_attack_report.json
"""

import time, secrets, random, json, statistics, sys, os
from typing import List, Tuple
from Crypto.Util.number import * 
# ----------------------------
# Miller-Rabin primality test
# ----------------------------
def is_probable_prime(n: int, k: int = 10) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits:int, k:int=10) -> int:
    """Generate a probable prime with 'bits' bits."""
    while True:
        p = secrets.randbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(p, k=k):
            return p

# ----------------------------
# RSA key generation
# ----------------------------
def gen_rsa(key_part_bits=256):
    p = gen_prime(key_part_bits)
    q = gen_prime(key_part_bits)
    n = p * q
    e = 65537
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)
    return n, e, d, p, q

# ----------------------------
# Square-and-multiply with per-bit timing
# returns (result, [(bit,sq_ns,mul_ns), ...])
# AMP repeats multiply when bit==1 to amplify timing signal
# ----------------------------
def modexp_timing(c:int, d:int, n:int, amp:int=1) -> Tuple[int, List[Tuple[int,int,int]]]:
    res = 1
    timings = []
    bstr = bin(d)[2:]
    for ch in bstr:
        # square
        t0 = time.perf_counter_ns()
        res = (res * res) % n
        t1 = time.perf_counter_ns()
        sq = t1 - t0
        mul = 0
        bit = 1 if ch == '1' else 0
        if bit:
            t2 = time.perf_counter_ns()
            for _ in range(amp):
                res = (res * c) % n
            t3 = time.perf_counter_ns()
            mul = t3 - t2
        timings.append((bit, sq, mul))
    return res, timings

# ----------------------------
# Attacker functions: collect traces & recovery
# ----------------------------
def collect_traces(n:int, e:int, d:int, samples:int=300, amp:int=1, m_bits:int=16):
    traces = []
    for i in range(samples):
        m = random.randint(2, 2**m_bits)
        c = pow(m, e, n)
        res, timings = modexp_timing(c, d, n, amp=amp)
        per_bit = [t[1] + t[2] for t in timings]
        traces.append({
            "run": i,
            "m": m,
            "ok": (res == m),
            "per_bit": per_bit,
            "d_bits": [t[0] for t in timings]
        })
        if (i+1) % 50 == 0:
            print(f"[+] Collected {i+1}/{samples} traces (amp={amp})")
    return traces

def recover_by_median(traces):
    if not traces:
        return "", 0.0
    num_bits = len(traces[0]["per_bit"])
    medians = []
    for bi in range(num_bits):
        vals = [t["per_bit"][bi] for t in traces]
        medians.append(statistics.median(vals))
    threshold = statistics.median(medians)
    recovered = "".join("1" if v > threshold else "0" for v in medians)
    return recovered, threshold

def compare_bits(true_d:int, rec_bits:str):
    true_bits = bin(true_d)[2:]
    L = min(len(true_bits), len(rec_bits))
    diffs = [i for i in range(L) if true_bits[i] != rec_bits[i]]
    return {
        "true_len": len(true_bits),
        "rec_len": len(rec_bits),
        "num_diff": len(diffs),
        "diff_positions_sample": diffs[:40],
        "true_prefix": true_bits[:min(200,len(true_bits))],
        "rec_prefix": rec_bits[:min(200,len(rec_bits))]
    }

# ----------------------------
# Runner / demo
# ----------------------------
def run_demo(key_part_bits=256, samples=300, amp=100):
    print("Generating RSA key. This may take some time for large sizes...")
    n, e, d, p, q = gen_rsa(key_part_bits)
    print(f"RSA generated: n bits={n.bit_length()}, d bits={d.bit_length()}")
    report = {"n_bits": n.bit_length(), "d_bits": d.bit_length(), "runs": {}}
    print(f"\n--- Collecting traces (amp={amp}) ---")
    traces = collect_traces(n, e, d, samples=samples, amp=amp, m_bits=16)
    rec_bits, thresh = recover_by_median(traces)
    cmp = compare_bits(d, rec_bits)
    cmp.update({"amp": amp, "threshold": thresh, "sample_traces": len(traces)})
    report["runs"][str(amp)] = cmp
    print(f"AMP={amp} -> diffs={cmp['num_diff']} (recovered len {cmp['rec_len']}, true {cmp['true_len']})")
    print("True prefix  :", cmp["true_prefix"][:80])
    print("Recovered pref:", cmp["rec_prefix"][:80])
    # save report
    outpath = "kocher_attack_report.json"
    with open(outpath, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {outpath}")
    return report

if __name__ == "__main__":
    # Tunables: change KEY_PART_BITS to 512 for RSA-1024 (slower)
    KEY_PART_BITS = 256   # each prime bits -> RSA modulus ~512 bits; set to 512 for 1024-bit RSA
    SAMPLES = 2000         # number of traces to collect per AMP setting
    AMP = 100
    report = run_demo(key_part_bits=KEY_PART_BITS, samples=SAMPLES, amp=AMP)
    # summary
    for amp, info in report["runs"].items():
        print(f"AMP={amp}: diffs={info['num_diff']}, threshold={info['threshold']:.2f}")
    print("Done.")
