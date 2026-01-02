from Crypto.Util.number import *
from sage.all import *
import os
import itertools
import subprocess
def flatter(M):
    import os
    import re
    from subprocess import check_output
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = str(os.cpu_count())
    ret = subprocess.check_output(["flatter"], input=z.encode(), env=env)
    return matrix(M.nrows(), M.ncols(), map(int, re.findall(rb"-?\d+", ret)))

p = getPrime(1024)
q = getPrime(1024)
r = getPrime(1024)
print(f"p = {p}")
print(f"q = {q}")
print(f"r = {r}")

N = p * q * r
e = 65537
d = pow(e, -1, (p - 1) * (q - 1) * (r - 1))
print(f"N = {N}")

NUM_SAMPLES = 9
MSG = [os.urandom(32) for _ in range(NUM_SAMPLES)]

N_fault = []
N_bytes = long_to_bytes(N)
for i in range(NUM_SAMPLES):
    fault_val = (N_bytes[0] + i + 10) % 256
    if fault_val == N_bytes[0]: fault_val += 1

    nf_bytes = bytes([fault_val]) + N_bytes[1:]
    N_fault.append(bytes_to_long(nf_bytes))


sig_1 = [] 
sig_2 = []


Z = N
alpha_p = (Z // p) * inverse_mod(Z // p, p)
alpha_q = (Z // q) * inverse_mod(Z // q, q)
alpha_r = (Z // r) * inverse_mod(Z // r, r)

for i in range(NUM_SAMPLES):
    msg = bytes_to_long(MSG[i])
    sp = pow(msg, d, p)
    sq = pow(msg, d, q)
    sr = pow(msg, d, r)


    full_sig = (sp * alpha_p + sq * alpha_q + sr * alpha_r)

    sig_1.append(full_sig % N)
    sig_2.append(full_sig % N_fault[i])

v = []
for i in range(NUM_SAMPLES):
    # v[i] = sp*Ap + sq*Aq + sr*Ar (in Z, not mod N)
    val = crt([sig_1[i], sig_2[i]], [N, N_fault[i]])
    v.append(val)

print("-" * 20)
print("Attack phase started...")

num_primes = 3
num_ortho = NUM_SAMPLES - num_primes


K1 = 2 * N
dim1 = NUM_SAMPLES + 1
base1 = []

for i in range(NUM_SAMPLES):
    vec = [0] * dim1
    vec[0] = K1 * v[i]
    vec[i+1] = 1
    base1.append(vec)

M1 = Matrix(ZZ, base1)
print("Running LLL 1...")
reduced1 = M1.LLL()

ortho_vecs = []
for i in range(num_ortho):
    row = list(reduced1[i])
    ortho_vecs.append(row[1:])

print(f"Extracted {len(ortho_vecs)} orthogonal vectors.")


K2 = 2**2048
base2 = []


for i in range(NUM_SAMPLES):
    vec = []
    for j in range(num_ortho):
        vec.append(K2 * ortho_vecs[j][i]) 

    for j in range(NUM_SAMPLES):
        if i == j: vec.append(1)
        else: vec.append(0)
    base2.append(vec)

M2 = Matrix(ZZ, base2)
print("Running LLL 2...")
reduced2 = flatter(M2)

print("Attempting to factor...")


found_factors = set()


w_candidates = []
rows_to_check = min(reduced2.nrows(), 10) 
for r_idx in range(rows_to_check):
    val = reduced2[r_idx][num_ortho]
    w_candidates.append(val)

import itertools
coeffs = [-1, 0, 1]
combinations = list(itertools.product(coeffs, repeat=min(len(w_candidates), 3)))

for combo in combinations:
    if all(c==0 for c in combo): continue


    w_guess = sum(c*w for c, w in zip(combo, w_candidates[:3]))


    vals_to_check = [v[0] - w_guess, v[0] + w_guess]

    for val in vals_to_check:
        factor = gcd(val, N)
        if factor > 1 and factor < N:
            found_factors.add(factor)


final_primes = set()

candidates = list(found_factors)
for f in found_factors:
    candidates.append(N // f)

for i in range(len(candidates)):
    for j in range(i + 1, len(candidates)):
        g = gcd(candidates[i], candidates[j])
        if g > 1:
            if is_prime(g): final_primes.add(g)
            if is_prime(candidates[i] // g): final_primes.add(candidates[i] // g)
            if is_prime(candidates[j] // g): final_primes.add(candidates[j] // g)

for f in candidates:
    if is_prime(f): final_primes.add(f)

if len(final_primes) < 3 and len(final_primes) > 0:
    curr_primes = list(final_primes)
    rem = N
    for cp in curr_primes:
        rem //= cp
    if rem > 1 and is_prime(rem):
        final_primes.add(rem)

sorted_primes = sorted(list(final_primes))
print("-" * 20)
if len(sorted_primes) == 3:
    print("SUCCESS! Recovered all 3 primes:")
    print("p =", sorted_primes[0])
    print("q =", sorted_primes[1])
    print("r =", sorted_primes[2])

    if sorted_primes[0] * sorted_primes[1] * sorted_primes[2] == N:
        print("\nVerification: MATCH N!")
else:
    print(f"Found {len(sorted_primes)} primes: {sorted_primes}")
    print("Raw factors found:", list(found_factors))
