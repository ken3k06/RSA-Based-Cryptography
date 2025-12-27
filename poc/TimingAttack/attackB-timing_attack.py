#!/usr/bin/env python3
import csv, json, math, os, random, statistics, urllib.request
from typing import List, Dict, Tuple

BASE_URL = "http://127.0.0.1:8000"
PER_SET = 2000
TTHRESH = 2.0
MAX_BITS = 64
LOG_PATH = "timing_log.csv"
SEED = 1337
CHUNK = 1000

def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def inv_mod(a: int, n: int) -> int:
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("no inverse")
    return x % n

def mont_params(n: int) -> Tuple[int, int]:
    k = n.bit_length()
    r = 1 << k
    r_inv = inv_mod(r, n)
    n_prime = (r * r_inv - 1) // n
    return r, n_prime

def mon_pro(a: int, b: int, n: int, n_prime: int, r: int):
    t = a * b
    m = (t * n_prime) % r
    u = (t + m * n) // r
    if u >= n:
        return u - n, True
    return u, False

def next_square_sub_event(m: int, assumed_prefix: str, n: int, n_prime: int, r: int) -> bool:
    m_bar = (m * r) % n
    x = r % n
    for bit in assumed_prefix:
        x, _ = mon_pro(x, x, n, n_prime, r)
        if bit == "1":
            x, _ = mon_pro(m_bar, x, n, n_prime, r)
    _, sub_sq = mon_pro(x, x, n, n_prime, r)
    return sub_sq

def welch_t(g1: List[int], g0: List[int]) -> float:
    if len(g1) < 50 or len(g0) < 50:
        return 0.0
    m1, m0 = statistics.mean(g1), statistics.mean(g0)
    v1 = statistics.pvariance(g1)
    v0 = statistics.pvariance(g0)
    se = math.sqrt(v1 / len(g1) + v0 / len(g0) + 1e-12)
    return (m1 - m0) / se

def http_get_json(url: str) -> Dict:
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode())

def http_post_json(url: str, obj: Dict) -> Dict:
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def sign_batch(messages: List[int]) -> List[Dict]:
    if not messages:
        return []
    return http_post_json(BASE_URL + "/sign", {"messages": messages})["results"]

def sign_pool(pool: List[int]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for i in range(0, len(pool), CHUNK):
        res = sign_batch(pool[i:i+CHUNK])
        for row in res:
            out[int(row["m"])] = int(row["duration_ns"])
    return out

def build_pool(prefix0: str, prefix1: str, n: int, n_prime: int, r: int, need: int):
    items: List[Tuple[int, bool, bool]] = []
    pred0: Dict[int, bool] = {}
    pred1: Dict[int, bool] = {}
    c0t = c0f = c1t = c1f = 0
    seen = set()
    tries = 0
    diff_kept = 0
    same_kept = 0
    SOFT_TRIES = 20 * need

    while min(c0t, c0f, c1t, c1f) < need:
        tries += 1
        m = random.randrange(2, n - 1)
        if m in seen:
            continue
        seen.add(m)

        e0 = next_square_sub_event(m, prefix0, n, n_prime, r)
        e1 = next_square_sub_event(m, prefix1, n, n_prime, r)

        want0 = (e0 and c0t < need) or ((not e0) and c0f < need)
        want1 = (e1 and c1t < need) or ((not e1) and c1f < need)

        take = False
        if e0 != e1:
            take = want0 or want1
        else:
            if tries > SOFT_TRIES:
                take = want0 or want1
            else:
                take = False

        if not take:
            continue

        items.append((m, e0, e1))
        pred0[m] = e0
        pred1[m] = e1

        if e0:
            if c0t < need: c0t += 1
        else:
            if c0f < need: c0f += 1

        if e1:
            if c1t < need: c1t += 1
        else:
            if c1f < need: c1f += 1

        if e0 != e1:
            diff_kept += 1
        else:
            same_kept += 1

    items.sort(key=lambda t: (t[1] ^ t[2], ), reverse=True)
    pool = [m for (m, _, _) in items]
    return pool, pred0, pred1, diff_kept, same_kept

def score_from_pool(prefix_assumed: str, hyp_bit: str, pool: List[int], time_map: Dict[int, int],
                    pred_map: Dict[int, bool], bit_index: int, writer) -> Tuple[float, float]:
    t_msgs: List[int] = []
    f_msgs: List[int] = []

    for m in pool:
        ev = pred_map[m]
        if ev:
            if len(t_msgs) < PER_SET:
                t_msgs.append(m)
        else:
            if len(f_msgs) < PER_SET:
                f_msgs.append(m)
        if len(t_msgs) >= PER_SET and len(f_msgs) >= PER_SET:
            break

    tt = [time_map[m] for m in t_msgs]
    tf = [time_map[m] for m in f_msgs]

    for m in t_msgs:
        writer.writerow([bit_index, hyp_bit, 1, m, "", time_map[m], prefix_assumed])
    for m in f_msgs:
        writer.writerow([bit_index, hyp_bit, 0, m, "", time_map[m], prefix_assumed])

    tscore = welch_t(tt, tf)
    diff = (statistics.mean(tt) - statistics.mean(tf)) if tt and tf else 0.0
    return tscore, diff

def choose_bit(t0: float, d0: float, t1: float, d1: float) -> str:
    # Strong evidence for bit 0: t0 positive and large, t1 negative
    if t0 > TTHRESH and t1 < -TTHRESH:
        return "0"
    # Strong evidence for bit 1: t1 positive and large, t0 negative
    if t1 > TTHRESH and t0 < -TTHRESH:
        return "1"
    # Otherwise, choose the hypothesis with the more positive t-score
    # Positive t-score means the predicted subtractions are causing delays (correct pattern)
    return "0" if t0 > t1 else "1"

def main():
    random.seed(SEED)
    pub = http_get_json(BASE_URL + "/pubkey")
    n = int(pub["n"])
    e = int(pub["e"])
    r, n_prime = mont_params(n)

    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    with open(LOG_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["bit_index", "hyp_bit", "pred_set", "message", "signature", "duration_ns", "prefix_assumed"])

        prefix = "1"
        print("[client] nbits=%d e=%d" % (n.bit_length(), e))

        for j in range(1, MAX_BITS):
            p0 = prefix + "0"
            p1 = prefix + "1"

            pool, pred0, pred1, diff_kept, same_kept = build_pool(p0, p1, n, n_prime, r, PER_SET)
            time_map = sign_pool(pool)

            t0, d0 = score_from_pool(p0, "0", pool, time_map, pred0, j, w)
            t1, d1 = score_from_pool(p1, "1", pool, time_map, pred1, j, w)

            print("[pool] diff=%d same=%d size=%d" % (diff_kept, same_kept, len(pool)))

            choose = choose_bit(t0, d0, t1, d1)
            prefix += choose
            print("[bit %4d] t0=%6.2f diff0=%10.2f  t1=%6.2f diff1=%10.2f -> %s" % (j, t0, d0, t1, d1, choose))

        print(prefix)

if __name__ == "__main__":
    main()
