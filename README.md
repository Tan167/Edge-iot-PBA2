# Edge IoT prototype: sensor -> containerised edge -> Azure IoT Hub -> dashboard

```
sensor sim --HMAC-signed HTTP--> edge container --MQTT/TLS--> Azure IoT Hub --> dashboard
 (20 Hz temp+vib)               verify, detect,               (built-in Event Hub     (Flask + Chart.js)
                                summarise, SQLite queue        endpoint)
```

## Run

**Local, no Azure** (edge posts to the dashboard over HTTP, same code path otherwise):
```
cp .env.example .env     # set SENSOR_SHARED_KEY and ADMIN_KEY
docker compose up --build
# dashboard http://localhost:8000   edge metrics http://localhost:8080/metrics
```
**Simulate an outage:**
```
curl -XPOST localhost:8080/admin/network -H 'X-Admin-Key: <ADMIN_KEY>' -d '{"up":false}'
# wait 30-60 s: watch queue_depth rise in /metrics, dashboard goes stale
curl -XPOST localhost:8080/admin/network -H 'X-Admin-Key: <ADMIN_KEY>' -d '{"up":true}'
```
**With Azure IoT Hub:**
```
az iot hub create --name <hub> --resource-group <rg> --sku F1 --partition-count 2
az iot hub device-identity create --hub-name <hub> --device-id edge-01
az iot hub device-identity connection-string show --hub-name <hub> --device-id edge-01
az iot hub connection-string show --hub-name <hub> --policy-name service --default-eventhub
```
Put the first string in `IOTHUB_DEVICE_CONNECTION_STRING`, the second in
`EVENTHUB_CONNECTION_STRING`, then `docker compose up --build`.
(The F1 free tier allows 8,000 messages/day: naive 20 Hz forwarding is 1.7 M/day,
the edge design is about 2.5 K/day. Untested against a live hub in this build.)

**Benchmark (no Docker needed):** `pip install flask psutil requests && python bench/run_bench.py --compare`
Under Docker use `docker stats` for CPU/memory.

## What the edge does
| Stage | Implementation |
|---|---|
| Local anomaly detection | EWMA mean/variance per metric, z > 4.5 (std floored), hard limits, no learning from anomalies |
| Send only what's needed | one summary (n, min/max/mean, anomaly count) per 10 s + one alert on the rising edge of an anomaly. Raw readings never leave the edge |
| Outage queueing | SQLite (WAL) queue on a volume; batches of up to 20; alerts drain before summaries; exponential backoff to 5 s; bounded at 50 k rows (oldest summaries dropped first) |
| Security (Unit IV: communication protection) | HMAC-SHA256 over the exact request body, +/-30 s timestamp window, strictly increasing sequence number -> rejects tampered, unsigned, stale and replayed messages. Edge to cloud is protected by IoT Hub's TLS and per-device key |

## Measured results (90 s run, 20 Hz, 20 s outage at t=30 s; one laptop-class machine, processes not containers)
| Metric | Secure (HMAC) | Insecure |
|---|---|---|
| Sensor->edge round trip p50 / p95 / p99 | 2.29 / 3.26 / 4.70 ms | 2.27 / 3.24 / 4.47 ms |
| Edge decision time p50 / p95 | 150 / 267 us | 111 / 219 us |
| HMAC verify, mean | 31 us | n/a |
| Alert sensor->dashboard (not delayed), p50 / p95 | 4.2 / 5.8 ms | 4.2 / 7.1 ms |
| Detector precision / recall (per reading, 165 injected) | 1.00 / 1.00 | 1.00 / 1.00 |
| Cloud messages vs naive per-reading | 23 vs 1,801 (-98.7 %) | 23 vs 1,804 |
| Cloud bytes (incl. est. 120 B/msg framing) | 8.4 KB vs 400.6 KB (-97.9 %) | 8.5 KB vs 401.1 KB |
| Max queue depth / final depth | 3 / 0, all 25 events delivered | same |
| Worst delivery delay (outage backlog) | 12.5 s | 12.5 s |
| Edge CPU mean / RSS max | 2.3 % / 43 MB | 2.2 % / 43 MB |
| Queue DB on disk | 4 KB | 4 KB |

Security checks (secure mode): valid 200, tampered 401, unsigned 401, replayed 409.

Caveats: the detector scores perfectly because the injected anomalies are large and
synthetic; real data needs tuning. Local round trips exclude real WAN latency to Azure.
Secure vs insecure differences are within run-to-run noise except the ~30 us HMAC cost.
Alert latency uses one host clock; with real IoT Hub, sensor and cloud clocks differ.

## Trade-offs
**Security**
- HMAC is cheap (about 30 us, <1 % of a round trip) and stops tampering and replay, but
  gives integrity and authenticity only, **not confidentiality**; readings travel in clear
  on the sensor link. Add TLS/mTLS there if the link is untrusted.
- Shared symmetric key: one leaked key compromises every sensor that shares it. Use
  per-device keys and rotation; keep the key in a secret store, not an env file.
- The sequence-number check is in-memory, so it is cheap but a single-device simplification;
  multiple sensors need per-device counters. The +/-30 s window needs roughly synced clocks.
- Summarising shrinks the cloud attack surface and data exposure, but also removes raw
  data for forensics. Compromising the edge lets an attacker forge summaries.
- `/admin/network` is a demo control; remove it or restrict it in production.

**Operational**
- Edge intelligence cuts messages by about 99 % (and cost / free-tier quota), and alerts
  still arrive in milliseconds. The price is that the cloud sees only aggregates, so you
  cannot retrain or re-detect from history without sending raw samples, and the detector
  has to be versioned and updated at the edge.
- Store-and-forward gives no data loss through outages, but delays summaries by the
  outage length (12.5 s here), grows disk, and drops oldest summaries once the cap is hit.
  Delivery is at-least-once: a crash between send and delete can duplicate an event, so the
  cloud should dedupe on (device, t0/seq).
- Batching improves efficiency but delays non-urgent data by up to one window (10 s).
- Containers add isolation and easy updates for a small footprint (about 43 MB RSS here);
  real Docker overhead should be re-measured with `docker stats`.
