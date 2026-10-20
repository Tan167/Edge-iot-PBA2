"""Sensor simulator: temperature + vibration with injected anomaly bursts.

Each reading is signed (HMAC-SHA256 over the exact request body) when SECURE=1.
The `inj` field is simulation ground truth used only for evaluating the
detector; a real sensor would not send it.
"""
import argparse
import hashlib
import hmac
import json
import math
import os
import random
import statistics
import time

import requests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--edge", default=os.getenv("EDGE_URL", "http://edge:8080"))
    ap.add_argument("--rate", type=float, default=float(os.getenv("RATE_HZ", "20")))
    ap.add_argument("--duration", type=float, default=float(os.getenv("DURATION", "0")),
                    help="seconds; 0 = run forever")
    ap.add_argument("--burst-prob", type=float, default=0.005)
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()
    secure = os.getenv("SECURE", "1") == "1"
    key = os.getenv("SENSOR_SHARED_KEY", "dev-only-change-me").encode()
    device = os.getenv("DEVICE_ID", "edge-01")
    if a.seed is not None:
        random.seed(a.seed)

    s = requests.Session()
    seq = int(time.time() * 1000)  # monotonic across restarts
    burst_left, kind = 0, "temp"
    rtt, errors, sent = [], 0, 0
    start = time.perf_counter()
    nxt = start

    while a.duration == 0 or time.perf_counter() - start < a.duration:
        t = time.time()
        temp = 60 + 3 * math.sin(2 * math.pi * t / 120) + random.gauss(0, 0.4)
        vib = abs(random.gauss(0.4, 0.05))
        if burst_left == 0 and random.random() < a.burst_prob:
            burst_left, kind = random.randint(5, 15), random.choice(["temp", "vib"])
        inj = burst_left > 0
        if inj:
            burst_left -= 1
            if kind == "temp":
                temp += random.uniform(12, 20)
            else:
                vib += random.uniform(1.0, 1.5)
        seq += 1
        body = json.dumps({"device": device, "seq": seq, "ts": t, "temp": round(temp, 3),
                           "vib": round(vib, 4), "inj": inj}, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if secure:
            headers["X-Sig"] = hmac.new(key, body, hashlib.sha256).hexdigest()
        t1 = time.perf_counter()
        try:
            s.post(a.edge + "/ingest", data=body, headers=headers, timeout=2)
            rtt.append((time.perf_counter() - t1) * 1000)
        except requests.RequestException:
            errors += 1
        sent += 1
        nxt += 1 / a.rate
        time.sleep(max(0, nxt - time.perf_counter()))

    rtt.sort()
    q = lambda p: rtt[min(len(rtt) - 1, int(p * len(rtt)))] if rtt else None
    print(json.dumps({"sent": sent, "errors": errors, "rtt_ms_p50": q(.5), "rtt_ms_p95": q(.95),
                      "rtt_ms_p99": q(.99), "rtt_ms_mean": statistics.fmean(rtt) if rtt else None}))


if __name__ == "__main__":
    main()
