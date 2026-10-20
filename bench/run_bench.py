"""Local benchmark: launches dashboard + edge + sensor as processes, injects a
network outage, samples CPU/RSS, and reports response time, network use and
resource overhead. Run with --compare for secure (HMAC on) vs insecure (off).

For the containerised stack use `docker stats` for CPU/memory instead.
"""
import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import time

import psutil
import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH, EDGE = 18000, 18080
KEY = "bench-key"


def pctl(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p * len(v)))] if v else None


def wait_up(url):
    for _ in range(50):
        try:
            requests.get(url, timeout=0.5)
            return
        except requests.RequestException:
            time.sleep(0.2)
    raise RuntimeError("service did not start: " + url)


def security_check(secure):
    """Valid / tampered / replayed requests -> expected status codes."""
    def send(body, sig):
        return requests.post(f"http://localhost:{EDGE}/ingest", data=body,
                             headers={"X-Sig": sig, "Content-Type": "application/json"}).status_code
    seq = int(time.time() * 1000) - 10**6  # below the simulator's seq space
    mk = lambda s: json.dumps({"device": "x", "seq": s, "ts": time.time(), "temp": 60, "vib": .4},
                              separators=(",", ":")).encode()
    sign = lambda b: hmac.new(KEY.encode(), b, hashlib.sha256).hexdigest()
    good = mk(seq)
    r = {"valid": send(good, sign(good)),
         "tampered": send(good.replace(b"60", b"61"), sign(good)),
         "replayed": send(good, sign(good)),
         "unsigned": send(mk(seq + 1), "")}
    return r


def run(secure, duration, outage_at, outage_len):
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, SECURE="1" if secure else "0", SENSOR_SHARED_KEY=KEY,
               QUEUE_DB=os.path.join(tmp, "q.db"), DASHBOARD_URL=f"http://localhost:{DASH}",
               EDGE_URL=f"http://localhost:{EDGE}", ADMIN_KEY="k", WINDOW_SEC="10")
    py = sys.executable
    dash = subprocess.Popen([py, f"{ROOT}/dashboard/app.py"], env=dict(env, PORT=str(DASH)))
    edge = subprocess.Popen([py, f"{ROOT}/edge/app.py"], env=dict(env, PORT=str(EDGE)))
    try:
        wait_up(f"http://localhost:{DASH}/api/state")
        wait_up(f"http://localhost:{EDGE}/healthz")
        sec = security_check(secure)
        base = requests.get(f"http://localhost:{EDGE}/metrics").json()
        sim = subprocess.Popen([py, f"{ROOT}/sensor/sim.py", "--duration", str(duration),
                                "--seed", "7"], env=env, stdout=subprocess.PIPE, text=True)
        procs = {"edge": psutil.Process(edge.pid), "dashboard": psutil.Process(dash.pid),
                 "sensor": psutil.Process(sim.pid)}
        for p in procs.values():
            p.cpu_percent(None)
        samples = {k: {"cpu": [], "rss": []} for k in procs}
        t0, state = time.time(), 0
        while sim.poll() is None:
            time.sleep(1)
            el = time.time() - t0
            if state == 0 and el >= outage_at:
                requests.post(f"http://localhost:{EDGE}/admin/network", json={"up": False},
                              headers={"X-Admin-Key": "k"})
                state = 1
            if state == 1 and el >= outage_at + outage_len:
                requests.post(f"http://localhost:{EDGE}/admin/network", json={"up": True},
                              headers={"X-Admin-Key": "k"})
                state = 2
            for k, p in procs.items():
                try:
                    samples[k]["cpu"].append(p.cpu_percent(None))
                    samples[k]["rss"].append(p.memory_info().rss / 1e6)
                except psutil.NoSuchProcess:
                    pass
        simout = json.loads(sim.stdout.read().strip().splitlines()[-1])
        if state == 1:
            requests.post(f"http://localhost:{EDGE}/admin/network", json={"up": True},
                          headers={"X-Admin-Key": "k"})
        for _ in range(60):  # let the backlog drain
            m = requests.get(f"http://localhost:{EDGE}/metrics").json()
            if m["queue_depth"] == 0:
                break
            time.sleep(0.5)
        time.sleep(1)
        m = requests.get(f"http://localhost:{EDGE}/metrics").json()
        dsh = requests.get(f"http://localhost:{DASH}/api/state").json()
    finally:
        edge.terminate(); dash.terminate()
        edge.wait(); dash.wait()

    ov = m["cloud_msg_overhead"]
    n = m.get("readings", 0)
    naive_bytes = m.get("raw_bytes_in", 0) + n * ov
    edge_bytes = m.get("cloud_payload_bytes", 0) + m.get("cloud_msgs", 0) * ov
    e2e = [a["e2e_ms"] for a in dsh["alerts"]]
    live = [x for x in e2e if x < 2000]
    res = {
        "mode": "secure(HMAC)" if secure else "insecure", "duration_s": duration,
        "outage_s": [outage_at, outage_at + outage_len],
        "security_check_status": sec if secure else "n/a",
        "response_time": {
            "sensor_rtt_ms_p50": simout["rtt_ms_p50"], "sensor_rtt_ms_p95": simout["rtt_ms_p95"],
            "sensor_rtt_ms_p99": simout["rtt_ms_p99"],
            "edge_decision_us_p50": m["decision_us_p50"], "edge_decision_us_p95": m["decision_us_p95"],
            "hmac_verify_us_mean": m["hmac_us_mean"],
            "alert_e2e_ms_p50_live": pctl(live, .5), "alert_e2e_ms_p95_live": pctl(live, .95),
            "alerts_total": len(e2e), "alerts_delayed_gt2s": len(e2e) - len(live),
            "alert_e2e_ms_max_delayed": max(e2e) if e2e else None},
        "detection": {"precision": m["precision"], "recall": m["recall"],
                      "tp": m.get("tp", 0), "fp": m.get("fp", 0), "fn": m.get("fn", 0)},
        "network": {
            "readings": n, "naive_msgs": n, "edge_msgs": m.get("cloud_msgs", 0),
            "naive_bytes": naive_bytes, "edge_bytes": edge_bytes,
            "byte_reduction_pct": round(100 * (1 - edge_bytes / naive_bytes), 2),
            "msg_reduction_pct": round(100 * (1 - m.get("cloud_msgs", 0) / n), 2),
            "dashboard_bytes_rx": dsh["bytes"], "dashboard_events_rx": dsh["events"]},
        "resilience": {"max_queue_depth": m["max_queue_depth"], "send_failures": m.get("send_failures", 0),
                       "final_queue_depth": m["queue_depth"],
                       "delivery_delay_s_p50": m["delivery_delay_s_p50"],
                       "delivery_delay_s_max": m["delivery_delay_s_max"], "events_delivered": m.get("cloud_events", 0),
                       "sensor_errors": simout["errors"]},
        "resources": {k: {"cpu_pct_mean": round(sum(v["cpu"]) / max(1, len(v["cpu"])), 2),
                          "cpu_pct_max": round(max(v["cpu"] or [0]), 2),
                          "rss_mb_max": round(max(v["rss"] or [0]), 1)}
                      for k, v in samples.items()},
        "disk_queue_db_kb": round(os.path.getsize(os.path.join(tmp, "q.db")) / 1024, 1)}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--outage-at", type=int, default=30)
    ap.add_argument("--outage-len", type=int, default=20)
    ap.add_argument("--compare", action="store_true")
    a = ap.parse_args()
    out = []
    for secure in ([True, False] if a.compare else [True]):
        r = run(secure, a.duration, a.outage_at, a.outage_len)
        out.append(r)
        print(json.dumps(r, indent=2))
    os.makedirs(f"{ROOT}/results", exist_ok=True)
    json.dump(out, open(f"{ROOT}/results/results.json", "w"), indent=2)


if __name__ == "__main__":
    main()
