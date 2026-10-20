"""Cloud dashboard.

Ingest paths:
  * Azure: consumes the IoT Hub built-in Event Hub-compatible endpoint when
    EVENTHUB_CONNECTION_STRING is set.
  * Local mock: POST /ingest (used when the edge has no IoT Hub connection string).
"""
import collections
import json
import logging
import os
import threading
import time

from flask import Flask, jsonify, request

PORT = int(os.getenv("PORT", "8000"))
EH_CS = os.getenv("EVENTHUB_CONNECTION_STRING", "")
logging.getLogger("werkzeug").setLevel(logging.WARNING)
app = Flask(__name__)

lock = threading.Lock()
ST = {"summaries": collections.deque(maxlen=720), "alerts": collections.deque(maxlen=300),
      "msgs": 0, "bytes": 0, "events": 0, "last_rx": None}


def handle(body: str, recv: float):
    d = json.loads(body)
    with lock:
        ST["msgs"] += 1
        ST["bytes"] += len(body.encode())
        ST["last_rx"] = recv
        for e in d.get("events", []):
            ST["events"] += 1
            e["recv_at"] = recv
            if e["kind"] == "alert":
                e["e2e_ms"] = round((recv - e["sensor_ts"]) * 1000, 1)
                ST["alerts"].append(e)
            else:
                ST["summaries"].append(e)


@app.post("/ingest")
def ingest():
    handle(request.get_data(as_text=True), time.time())
    return "", 204


@app.get("/api/state")
def state():
    with lock:
        return jsonify(summaries=list(ST["summaries"]), alerts=list(ST["alerts"]),
                       msgs=ST["msgs"], bytes=ST["bytes"], events=ST["events"],
                       last_rx=ST["last_rx"], now=time.time())


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Edge IoT dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>body{font-family:system-ui;margin:16px;max-width:900px}
.k{display:flex;gap:12px;flex-wrap:wrap}.c{border:1px solid #8884;border-radius:8px;padding:8px 12px}
.c b{display:block;font-size:1.3em}table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid #8884;padding:4px;text-align:left;font-size:.85em}.bad{color:#d33}</style>
<h2>Edge IoT dashboard</h2>
<div class=k id=k></div>
<canvas id=ch height=120></canvas>
<h3>Alerts</h3><table id=al><tr><th>Time<th>Metric<th>Value<th>z<th>E2E ms</table>
<script>
const ch=new Chart(document.getElementById('ch'),{type:'line',data:{labels:[],datasets:[
{label:'temp mean',data:[],yAxisID:'y'},{label:'temp max',data:[],yAxisID:'y'},
{label:'vib max',data:[],yAxisID:'y2'}]},options:{animation:false,scales:{y:{position:'left'},y2:{position:'right'}}}});
async function tick(){const s=await (await fetch('/api/state')).json();
const age=s.last_rx?(s.now-s.last_rx):null;
document.getElementById('k').innerHTML=
`<div class=c>Cloud msgs<b>${s.msgs}</b></div><div class=c>Events<b>${s.events}</b></div>
<div class=c>Bytes rx<b>${s.bytes}</b></div><div class=c>Alerts<b>${s.alerts.length}</b></div>
<div class=c>Last data<b class="${age>20?'bad':''}">${age==null?'-':age.toFixed(0)+' s ago'}</b></div>`;
const sm=s.summaries.slice(-60);ch.data.labels=sm.map(e=>new Date(e.t1*1000).toLocaleTimeString());
ch.data.datasets[0].data=sm.map(e=>e.temp.mean);ch.data.datasets[1].data=sm.map(e=>e.temp.max);
ch.data.datasets[2].data=sm.map(e=>e.vib.max);ch.update();
document.getElementById('al').innerHTML='<tr><th>Time<th>Metric<th>Value<th>z<th>E2E ms</tr>'+
s.alerts.slice(-15).reverse().map(a=>`<tr><td>${new Date(a.sensor_ts*1000).toLocaleTimeString()}<td>${a.metric}<td>${a.value}<td>${a.z}<td class="${a.e2e_ms>5000?'bad':''}">${a.e2e_ms}`).join('');}
setInterval(tick,2000);tick();
</script>"""


@app.get("/")
def index():
    return PAGE


def eventhub_consumer():
    from azure.eventhub import EventHubConsumerClient
    client = EventHubConsumerClient.from_connection_string(EH_CS, consumer_group="$Default")

    def on_event(ctx, event):
        if event:
            handle(event.body_as_str(), time.time())

    with client:
        client.receive(on_event=on_event, starting_position="@latest")


if __name__ == "__main__":
    if EH_CS:
        threading.Thread(target=eventhub_consumer, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
