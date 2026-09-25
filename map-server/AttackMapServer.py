#!/usr/bin/env python3
"""Redis-backed live map server for host-net-monitor activity."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    import redis
except ImportError as exc:  # pragma: no cover - exercised by startup
    redis = None
    REDIS_IMPORT_ERROR = exc

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Host network activity map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="">
<style>
:root{color-scheme:dark;--panel:#101826;--muted:#9caec5;--line:#25344a}*{box-sizing:border-box}body{margin:0;background:#08111e;color:#e8eef7;font:14px system-ui,sans-serif}header{height:58px;padding:10px 18px;background:#101b2d;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:18px}h1{font-size:17px;margin:0;white-space:nowrap}.stats{display:flex;gap:18px;color:var(--muted);font-size:12px}.stats b{color:#f5f8fc;font-size:15px;margin-left:4px}main{display:grid;grid-template-columns:minmax(0,1fr) 440px;height:calc(100vh - 58px)}#map{height:100%;min-height:420px}.side{overflow:auto;background:var(--panel);border-left:1px solid var(--line);padding:14px}.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:10px;color:var(--muted)}button,select{background:#1b2a40;color:#e8eef7;border:1px solid #39506f;border-radius:5px;padding:5px 8px}table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;color:var(--muted);position:sticky;top:0;background:var(--panel);padding:8px 5px;border-bottom:1px solid var(--line)}td{padding:8px 5px;border-bottom:1px solid #1d2a3d;vertical-align:top}td.num{text-align:right;font-variant-numeric:tabular-nums}.city{font-weight:600}.country,.sub{color:var(--muted);font-size:11px}.rep{color:#ffbd69}.empty{color:var(--muted);padding:22px 5px}.legend{background:#101826dd;padding:8px;border:1px solid #39506f;border-radius:4px;line-height:1.6}.swatch{display:inline-block;width:14px;height:10px;margin-right:5px;border-radius:2px}
@media(max-width:900px){main{grid-template-columns:1fr;height:auto}.side{height:50vh;border-left:0;border-top:1px solid var(--line)}#map{height:50vh}.stats{gap:8px}}
</style></head><body><header><h1>Host network activity</h1><div class="stats"><span>Cities<b id="cities">0</b></span><span>Flows<b id="flows">0</b></span><span>Bandwidth<b id="bytes">0 B</b></span><span>Updated<b id="updated">—</b></span></div></header>
<main><div id="map"></div><section class="side"><div class="toolbar"><label>Display <select id="display"><option value="shade">Activity shading</option><option value="lines">Weighted lines</option></select></label><button id="refresh">Refresh</button><span id="status"></span></div><table><thead><tr><th>City</th><th>IP</th><th>Reputation</th><th class="num">Bandwidth</th><th class="num">Flows</th></tr></thead><tbody id="rows"></tbody></table><div id="empty" class="empty" hidden>No enriched network activity found.</div></section></main>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script><script>
const map=L.map('map',{worldCopyJump:true}).setView([25,0],2);L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{attribution:'© OpenStreetMap contributors',maxZoom:18}).addTo(map);const layer=L.layerGroup().addTo(map);let mode='shade';
const home=__HOME__; const fmtBytes=n=>{if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;if(n<1073741824)return `${(n/1048576).toFixed(1)} MB`;return `${(n/1073741824).toFixed(1)} GB`};const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function color(v,max){const x=Math.max(0,Math.min(1,v/(max||1)));return `hsl(${Math.round(215-205*x)} 90% ${Math.round(65-20*x)}%)`}
function render(d){layer.clearLayers();document.querySelector('#cities').textContent=d.cities.length;document.querySelector('#flows').textContent=d.total_flow_count.toLocaleString();document.querySelector('#bytes').textContent=fmtBytes(d.total_bytes);document.querySelector('#updated').textContent=d.updated||'—';const max=Math.max(...d.cities.map(x=>x.metric),1);for(const c of d.cities){if(c.latitude==null||c.longitude==null)continue;const col=color(c.metric,max), radius=mode==='shade'?Math.max(8,Math.min(42,8+34*c.metric/max)):Math.max(5,Math.min(22,5+17*c.metric/max));const marker=L.circle([c.latitude,c.longitude],{radius:radius*3000,color:col,weight:2,fillColor:col,fillOpacity:mode==='shade'?.62:.2});marker.bindPopup(`<b>${esc(c.city||'Unknown city')}</b><br>${esc(c.country||'')}<br>${fmtBytes(c.bytes)} · ${c.flow_count.toLocaleString()} flows`);marker.addTo(layer);if(mode==='lines'){const line=L.polyline([home,[c.latitude,c.longitude]],{color:col,weight:Math.max(1,Math.min(12,1+10*c.metric/max)),opacity:.8});line.bindTooltip(`${esc(c.city||'Unknown city')}: ${fmtBytes(c.bytes)} / ${c.flow_count} flows`);line.addTo(layer)}}const rows=document.querySelector('#rows');rows.innerHTML=d.rows.map(r=>`<tr><td><div class="city">${esc(r.city||'Unknown')}</div><div class="country">${esc(r.country||'')}</div></td><td><div>${esc(r.ip)}</div><div class="sub">${esc(r.timestamp||'')}</div></td><td class="rep">${esc(r.reputation||'—')}</td><td class="num">${fmtBytes(r.bytes)}</td><td class="num">${r.flow_count.toLocaleString()}</td></tr>`).join('');document.querySelector('#empty').hidden=d.rows.length>0}
async function load(){const s=document.querySelector('#status');s.textContent='Loading…';try{const r=await fetch('/api/activity?limit=5000',{cache:'no-store'});if(!r.ok)throw Error(await r.text());render(await r.json());s.textContent='Live';}catch(e){s.textContent='Error';console.error(e)}}document.querySelector('#display').onchange=e=>{mode=e.target.value;load()};document.querySelector('#refresh').onclick=load;load();setInterval(load,5000);
const legend=L.control({position:'bottomright'});legend.onAdd=()=>{const d=L.DomUtil.create('div','legend');d.innerHTML='<b>Activity</b><br><span class="swatch" style="background:#34c7eb"></span>low<br><span class="swatch" style="background:#f2d33b"></span>medium<br><span class="swatch" style="background:#f35b4f"></span>high';return d};legend.addTo(map);
</script></body></html>"""


def number(item, *keys):
    for key in keys:
        value = item.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return int(value)
    return 0


def city_name(item: dict) -> str:
    geo = item.get("geo") or {}
    return str(geo.get("city_name") or geo.get("city") or "Unknown city")


def aggregate(rows: list[dict]) -> dict:
    cities: dict[tuple[str, str], dict] = defaultdict(lambda: {"flow_count": 0, "bytes": 0, "latitude": None, "longitude": None})
    for item in rows:
        geo = item.get("geo") or {}
        lat, lon = geo.get("latitude"), geo.get("longitude")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            continue
        key = (city_name(item), str(geo.get("country_name") or geo.get("country_code") or ""))
        out = cities[key]
        out["flow_count"] += number(item, "flow_count", "flows", "flowcount")
        out["bytes"] += number(item, "flow_byte_sum", "bytes_count", "bytes", "byte_count")
        out["latitude"], out["longitude"] = float(lat), float(lon)
    city_list = []
    for (city, country), value in cities.items():
        value.update(city=city, country=country, metric=value["bytes"])
        city_list.append(value)
    city_list.sort(key=lambda x: (x["metric"], x["flow_count"]), reverse=True)
    row_items = []
    for item in reversed(rows):
        geo = item.get("geo") or {}
        rep = item.get("reputation") or {}
        matches = rep.get("matches") if isinstance(rep, dict) else None
        if isinstance(matches, list):
            reputation = ", ".join(str(m.get("category") or m.get("source") or "match") for m in matches if isinstance(m, dict))
        else:
            reputation = str(rep.get("status") or "") if isinstance(rep, dict) else ""
        row_items.append({"city": city_name(item), "country": str(geo.get("country_name") or geo.get("country_code") or ""), "ip": str(item.get("external_ip") or item.get("ip") or "—"), "timestamp": str(item.get("timestamp") or ""), "bytes": number(item, "flow_byte_sum", "bytes_count", "bytes", "byte_count"), "flow_count": number(item, "flow_count", "flows", "flowcount"), "reputation": reputation})
    row_items.sort(key=lambda x: (x["bytes"], x["flow_count"]), reverse=True)
    latest = max((x.get("timestamp", "") for x in rows), default="")
    return {"updated": latest, "total_flow_count": sum(x["flow_count"] for x in city_list), "total_bytes": sum(x["bytes"] for x in city_list), "cities": city_list, "rows": row_items}


def read_stream(client, stream: str, limit: int) -> list[dict]:
    entries = client.xrevrange(stream, count=limit)
    rows = []
    for _entry_id, fields in reversed(entries):
        payload = fields.get(b"payload", fields.get("payload"))
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", "replace")
        try:
            value = json.loads(payload)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


class Handler(BaseHTTPRequestHandler):
    server_version = "HostNetMap/2.0"

    def _send_json(self, status: int, value: dict):
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if urlparse(self.path).path != "/api/events":
            self.send_error(404); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > self.server.max_body_bytes:
                self._send_json(413, {"error": "request body is empty or too large"}); return
            raw = self.rfile.read(length).decode("utf-8")
            accepted = 0
            for line in raw.splitlines():
                if not line.strip(): continue
                value = json.loads(line)
                if not isinstance(value, dict): raise ValueError("each line must be a JSON object")
                self.server.redis.xadd(self.server.stream, {"payload": json.dumps(value, separators=(",", ":"))}, maxlen=self.server.max_stream_length, approximate=True)
                accepted += 1
            self._send_json(202, {"accepted": accepted, "stream": self.server.stream})
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._send_json(503, {"error": f"redis write failed: {exc}"})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/activity":
            query = parse_qs(parsed.query)
            try: limit = max(1, min(10000, int(query.get("limit", [self.server.limit])[0])))
            except ValueError: limit = self.server.limit
            try: self._send_json(200, aggregate(read_stream(self.server.redis, self.server.stream, limit)))
            except Exception as exc: self._send_json(503, {"error": f"redis read failed: {exc}"})
            return
        if parsed.path in ("/", "/index.html"):
            body = INDEX_HTML.replace("__HOME__", json.dumps([self.server.home_lat, self.server.home_lon])).encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        self.send_error(404)

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-url", default="redis://127.0.0.1:6379/0", help="Redis URL (default: redis://127.0.0.1:6379/0)")
    parser.add_argument("--redis-stream", default="host-net-monitor:events")
    parser.add_argument("--redis-maxlen", type=int, default=100000)
    parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--home-lat", type=float, default=64.1466); parser.add_argument("--home-lon", type=float, default=-21.9426); parser.add_argument("--limit", type=int, default=5000)
    args = parser.parse_args()
    if redis is None: parser.error(f"install map-server/requirements.txt ({REDIS_IMPORT_ERROR})")
    client = redis.Redis.from_url(args.redis_url)
    try: client.ping()
    except Exception as exc: parser.error(f"cannot connect to Redis at {args.redis_url}: {exc}")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.redis = client; server.stream = args.redis_stream; server.max_stream_length = max(100, args.redis_maxlen); server.home_lat = args.home_lat; server.home_lon = args.home_lon; server.limit = max(1, min(10000, args.limit)); server.max_body_bytes = 8 * 1024 * 1024
    print(f"Map server listening on http://{args.host}:{args.port} (Redis stream {args.redis_stream})")
    server.serve_forever()


if __name__ == "__main__": main()
