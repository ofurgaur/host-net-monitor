# Host network map server

`AttackMapServer.py` serves a live Leaflet map backed by the host monitor's `network-flows.jsonl` and `network-ips.jsonl` files. It reloads the JSONL files every five seconds, so it can be run beside the monitor.

```sh
python3 map-server/AttackMapServer.py \
  --flow-log ./network-flows.jsonl \
  --ip-log ./network-ips.jsonl \
  --port 8080
```

Open <http://127.0.0.1:8080/>. The default view shades city activity by bandwidth. Select **Weighted lines** to draw lines from the configured host location to each city; line width and color are based on the selected city's bandwidth. The table shows city, IP, reputation (when present), bandwidth, and flow count.

Use `--home-lat` and `--home-lon` to set the local host's map origin. The server has no Python dependencies; the browser loads Leaflet and OpenStreetMap tiles from their public CDNs.
