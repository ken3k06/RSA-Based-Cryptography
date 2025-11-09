from sage.all import *
from Crypto.Util.number import *
import time
import random
import json

p = getPrime(512)
q = getPrime(512)
n = p * q

e = 65537
d = pow(e,-1,(p-1)*(q-1))
print(bin(d)[2:])


print(f"p={p}")
print(f"q={q}")
print(f"n={n}")
print(f"d={d}")
def check_diff(bin1:str,bin2:str) -> int:
    count = 0
    for i,(a,b) in enumerate(zip(bin1,bin2)):
        if a!=b:
            count +=1
            print(f"diff at {i}")
    return count 


def decrypt_rsa(c, d, n):
    c %= n
    res = 1
    bit_time = []
    for bit in bin(d)[2:]:
        t0 = time.perf_counter_ns()
        res = (res * res) % n
        t1 = time.perf_counter_ns()
        sq_time = t1 - t0

        mul_time = 0
        if bit == '1':
            t2 = time.perf_counter_ns()
            res = (res * c) % n
            t3 = time.perf_counter_ns()
            mul_time = t3 - t2

        bit_time.append((int(bit), sq_time, mul_time))
    return res, bit_time

if __name__ == "__main__":
    results = []

    for i in range(750):
        m = random.randint(2, n - 2)
        c = pow(m, e, n)

        m_dec, times = decrypt_rsa(c, d, n)
        ok = (m_dec == m)

        per_bit = [t[1] + t[2] for t in times]
        total_time = sum(per_bit)

        results.append({
            "run": i,
            "ok": ok,
            "total_time_ns": total_time,
            "per_bit_time_ns": per_bit
        })

    with open("output.json", "w") as f:
        json.dump(results, f, indent=2)



    import json
    import statistics

    with open("output.json", "r") as f:
        runs = json.load(f)

    num_runs = len(runs)
    num_bits = len(runs[0]["per_bit_time_ns"])

    mean_per_bit = []
    for bit_idx in range(num_bits):
        samples = [runs[r]["per_bit_time_ns"][bit_idx] for r in range(num_runs)]
        mean_t = statistics.mean(samples)
        mean_per_bit.append(mean_t)

    base_threshold = statistics.median(mean_per_bit)

    def recover_bits(threshold):
        return "".join(
            "1" if mean_t > threshold else "0"
            for mean_t in mean_per_bit
        )

    print("Số lần đo:", num_runs)
    print("Số bit của d quan sát được:", num_bits)
    print("Ngưỡng median:", base_threshold)
    rec_median = recover_bits(base_threshold)
    print("\n[median] Chuỗi bit d khôi phục ")
    print(rec_median)

    a = str(bin(d)[2:])
    b = str(rec_median)
    print(check_diff(a,b))



