"""Edge application: verify -> detect -> summarise -> queue -> send.

Pipeline per reading (HTTP POST /ingest from the sensor simulator):
  1. Communication protection (Unit IV): HMAC-SHA256 signature + timestamp
     window + strictly increasing sequence number (tamper / replay defence).
  2. Local anomaly detection: EWMA mean/variance z-score per metric.
  3. Aggregation: a summary per WINDOW_SEC; a single alert on the rising edge
     of an anomaly. Raw readings are never forwarded.
  4. Store-and-forward: events go to a SQLite queue (survives restarts and
     outages); a sender thread drains it in batches, alerts first.
  5. Transport: Azure IoT Hub (MQTT/TLS) if IOTHUB_DEVICE_CONNECTION_STRING is
     set, otherwise HTTP to the dashboard (local mock of the cloud path).
"""
import collections
import hashlib
import hmac
import json
import logging
import math
import os
import sqlite3
import threading
import time

import psutil
import requests
from flask import Flask, jsonify, request

DEVICE_ID = os.getenv("DEVICE_ID", "edge-01")
SHARED_KEY = os.getenv("SENSOR_SHARED_KEY", "dev-only-change-me").encode()
ADMIN_KEY = os.getenv("ADMIN_KEY", "admin-dev")
SECURE = os.getenv("SECURE", "1") == "1"
WINDOW_SEC = float(os.getenv("WINDOW_SEC", "10"))
BATCH_MAX = int(os.getenv("BATCH_MAX", "20"))
DB_PATH = os.getenv("QUEUE_DB", "/data/queue.db")
QUEUE_MAX_ROWS = int(os.getenv("QUEUE_MAX_ROWS", "50000"))
IOTHUB_CS = os.getenv("IOTHUB_DEVICE_CONNECTION_STRING", "")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://dashboard:8000")
PORT = int(os.getenv("PORT", "8080"))
MAX_SKEW_SEC = 30
CLOUD_MSG_OVERHEAD = 120  # est. MQTT/TLS framing bytes per cloud message

logging.getLogger("werkzeug").setLevel(logging.WARNING)
app = Flask(__name__)
PROC = psutil.Process()
PROC.cpu_percent(None)


# ----------------------------------------------------------------- detector
class EwmaDetector:
    """Flags x if |x-mean| > z*std (std floored). Does not learn from anomalies."""

    def __init__(self, alpha, z, warmup, min_std, hard_hi):
        self.alpha, self.z, self.warmup = alpha, z, warmup
        self.min_std, self.hard_hi = min_std, hard_hi
        self.n, self.mean, self.var, self.streak = 0, 0.0, 0.0, 0

    def update(self, x):
        self.n += 1
        if self.n == 1:
            self.mean = x
            return False, 0.0
        std = max(math.sqrt(self.var), self.min_std)
        z = abs(x - self.mean) / std
        bad = self.n > self.warmup and (z > self.z or x > self.hard_hi)
        if bad:
            self.streak += 1
            if self.streak > 40:  # persistent level shift: re-learn
                self.mean, self.var, self.streak = x, 0.0, 0
            return True, z
        self.streak = 0
        d = x - self.mean
        self.mean += self.alpha * d
        self.var = (1 - self.alpha) * (self.var + self.alpha * d * d)
        return False, z


det = {
    "temp": EwmaDetector(0.05, 4.5, 40, 0.5, 85.0),
    "vib": EwmaDetector(0.05, 4.5, 40, 0.03, 2.0),
}


# -------------------------------------------------------------------- queue
class Queue:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS q(id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " prio INT, body TEXT)")
        self.lock, self.puts, self.max_depth = threading.Lock(), 0, 0

    def put(self, prio, body):
        with self.lock:
            self.db.execute("INSERT INTO q(prio,body) VALUES(?,?)", (prio, body))
            self.puts += 1
            self.max_depth = max(self.max_depth, self._depth())
            if self.puts % 100 == 0 and self._depth() > QUEUE_MAX_ROWS:
                # bounded disk: drop oldest low-priority summaries first
                self.db.execute(
                    "DELETE FROM q WHERE id IN (SELECT id FROM q WHERE prio=0"
                    " ORDER BY id LIMIT ?)", (self._depth() - QUEUE_MAX_ROWS,))

    def peek(self, n):
        with self.lock:
            return self.db.execute(
                "SELECT id, body FROM q ORDER BY prio DESC, id LIMIT ?", (n,)).fetchall()

    def delete(self, ids):
        with self.lock:
            self.db.executemany("DELETE FROM q WHERE id=?", [(i,) for i in ids])

    def _depth(self):
        return self.db.execute("SELECT COUNT(*) FROM q").fetchone()[0]

    def depth(self):
        with self.lock:
            return self._depth()


queue = Queue(DB_PATH)
wake = threading.Event()
NET = {"up": True}  # simulated link state, toggled via /admin/network


# ---------------------------------------------------------------- transports
class IoTHubTransport:
    def __init__(self, cs):
        from azure.iot.device import IoTHubDeviceClient  # lazy: optional dep
        self.client = IoTHubDeviceClient.create_from_connection_string(cs)
        self.client.connect()

    def send(self, payload: str):
        from azure.iot.device import Message
        m = Message(payload, content_encoding="utf-8", content_type="application/json")
        self.client.send_message(m)


class HttpMockTransport:
    def send(self, payload: str):
        r = requests.post(DASHBOARD_URL + "/ingest", data=payload,
                          headers={"Content-Type": "application/json"}, timeout=3)
        r.raise_for_status()


transport = IoTHubTransport(IOTHUB_CS) if IOTHUB_CS else HttpMockTransport()


# ------------------------------------------------------------------ metrics
class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.c = collections.Counter()
        self.decision_us = collections.deque(maxlen=20000)
        self.hmac_us = collections.deque(maxlen=20000)
        self.delay_s = []  # delivery delay per event (event time -> cloud send)

    def inc(self, k, v=1):
        with self.lock:
            self.c[k] += v


M = Metrics()


def pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    return s[min(len(s) - 1, int(p / 100 * len(s)))]


# -------------------------------------------------------------------- state
state_lock = threading.Lock()
S = {"last_seq": 0, "in_anom": False}
win = {"t0": time.time(), "n": 0, "anoms": 0,
       "temp": [1e9, -1e9, 0.0], "vib": [1e9, -1e9, 0.0]}


def reset_window():
    win.update(t0=time.time(), n=0, anoms=0, temp=[1e9, -1e9, 0.0], vib=[1e9, -1e9, 0.0])


def flush_window():
    with state_lock:
        if win["n"] == 0:
            reset_window()
            return
        n = win["n"]
        ev = {"kind": "summary", "device": DEVICE_ID, "t0": win["t0"], "t1": time.time(),
              "n": n, "anoms": win["anoms"]}
        for k in ("temp", "vib"):
            lo, hi, tot = win[k]
            ev[k] = {"min": round(lo, 3), "max": round(hi, 3), "mean": round(tot / n, 3)}
        reset_window()
    queue.put(0, json.dumps(ev, separators=(",", ":")))
    wake.set()


def window_timer():
    while True:
        time.sleep(WINDOW_SEC)
        flush_window()


# ------------------------------------------------------------------- sender
def sender():
    backoff = 0.5
    while True:
        rows = queue.peek(BATCH_MAX)
        if not rows:
            wake.wait(1.0)
            wake.clear()
            continue
        ids = [r[0] for r in rows]
        events = [json.loads(r[1]) for r in rows]
        payload = json.dumps({"device": DEVICE_ID, "sent_at": time.time(), "events": events},
                             separators=(",", ":"))
        try:
            if not NET["up"]:
                raise ConnectionError("simulated outage")
            transport.send(payload)
        except Exception:
            M.inc("send_failures")
            time.sleep(backoff)
            backoff = min(backoff * 2, 5.0)
            continue
        queue.delete(ids)
        backoff = 0.5
        M.inc("cloud_msgs")
        M.inc("cloud_payload_bytes", len(payload))
        M.inc("cloud_events", len(events))
        now = time.time()
        with M.lock:
            M.delay_s.extend(now - (e.get("detected_at") or e["t1"]) for e in events)


# ------------------------------------------------------------------- routes
@app.post("/ingest")
def ingest():
    t0 = time.perf_counter()
    raw = request.get_data()
    if SECURE:
        th = time.perf_counter()
        expect = hmac.new(SHARED_KEY, raw, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(request.headers.get("X-Sig", ""), expect)
        M.hmac_us.append((time.perf_counter() - th) * 1e6)
        if not ok:
            M.inc("rejected_signature")
            return jsonify(error="bad signature"), 401
    try:
        d = json.loads(raw)
        temp, vib, seq, ts = float(d["temp"]), float(d["vib"]), int(d["seq"]), float(d["ts"])
    except Exception:
        M.inc("rejected_malformed")
        return jsonify(error="malformed"), 400
    now = time.time()
    if SECURE and abs(now - ts) > MAX_SKEW_SEC:
        M.inc("rejected_stale")
        return jsonify(error="stale"), 401

    alert = None
    with state_lock:
        if SECURE:
            if seq <= S["last_seq"]:
                M.inc("rejected_replay")
                return jsonify(error="replay"), 409
            S["last_seq"] = seq
        rt, rv = det["temp"].update(temp), det["vib"].update(vib)
        anomaly = rt[0] or rv[0]
        if anomaly and not S["in_anom"]:
            metric, val, z = ("temp", temp, rt[1]) if rt[0] else ("vib", vib, rv[1])
            alert = {"kind": "alert", "device": DEVICE_ID, "metric": metric,
                     "value": round(val, 3), "z": round(z, 1), "seq": seq,
                     "sensor_ts": ts, "detected_at": now}
        S["in_anom"] = anomaly
        win["n"] += 1
        win["anoms"] += int(anomaly)
        for k, v in (("temp", temp), ("vib", vib)):
            w = win[k]
            w[0], w[1], w[2] = min(w[0], v), max(w[1], v), w[2] + v
    if alert:
        queue.put(1, json.dumps(alert, separators=(",", ":")))
        wake.set()

    M.decision_us.append((time.perf_counter() - t0) * 1e6)
    M.inc("readings")
    M.inc("raw_bytes_in", len(raw))
    if "inj" in d:  # evaluation-only ground truth from the simulator
        M.inc(("tp" if anomaly else "fn") if d["inj"] else ("fp" if anomaly else "tn"))
    return jsonify(anomaly=anomaly, seq=seq)


@app.get("/metrics")
def metrics():
    with M.lock:
        c = dict(M.c)
    tp, fp, fn = c.get("tp", 0), c.get("fp", 0), c.get("fn", 0)
    c.update(
        queue_depth=queue.depth(), max_queue_depth=queue.max_depth,
        delivery_delay_s_p50=pct(M.delay_s, 50), delivery_delay_s_max=max(M.delay_s, default=None), net_up=NET["up"],
        decision_us_p50=pct(M.decision_us, 50), decision_us_p95=pct(M.decision_us, 95),
        hmac_us_mean=(sum(M.hmac_us) / len(M.hmac_us)) if M.hmac_us else None,
        precision=tp / (tp + fp) if tp + fp else None,
        recall=tp / (tp + fn) if tp + fn else None,
        cpu_pct=PROC.cpu_percent(None), rss_mb=PROC.memory_info().rss / 1e6,
        secure=SECURE, cloud_msg_overhead=CLOUD_MSG_OVERHEAD,
        transport="iothub" if IOTHUB_CS else "http-mock")
    return jsonify(c)


@app.post("/admin/network")
def admin_network():
    if not hmac.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY):
        return jsonify(error="forbidden"), 403
    NET["up"] = bool(request.get_json(force=True).get("up", True))
    return jsonify(net_up=NET["up"])


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    threading.Thread(target=window_timer, daemon=True).start()
    threading.Thread(target=sender, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
