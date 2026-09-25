# Host network map server

The map server uses a Redis stream as its only data source. It does not read the monitor's JSONL files. Start Redis, install the small Python dependency, and run:

```sh
python3 -m pip install -r map-server/requirements.txt
python3 map-server/AttackMapServer.py --redis-url redis://127.0.0.1:6379/0
```

Post one or more JSONL records to the ingestion API:

```sh
curl -X POST -H 'Content-Type: application/x-ndjson' \
  --data-binary @network-flows.jsonl \
  http://127.0.0.1:8080/api/events
```

The API stores each JSON object in the configured Redis stream (`host-net-monitor:events` by default). The browser polls `/api/activity`, which aggregates the recent stream records by city and displays bandwidth, flow count, IP, and reputation. Activity shading is the default map view; weighted lines can be selected in the UI.

## Experimental JSONL tailer

This helper follows the monitor's files and posts new lines to Redis through the map server. It splits individual JSONL lines into chunks and sends exactly one chunk every two seconds, so it works even though the monitor writes a new window only every 30 seconds. It is deliberately separate from the server so production deployments can send events through another collector later.

```sh
python3 map-server/tail_jsonl.py \
  --file network-flows.jsonl \
  --file network-ips.jsonl \
  --start-at-end \
  --chunk-seconds 2 \
  --chunk-lines 10
```

Use `--start-at-end` to ignore existing records. Without it, existing lines are forwarded first and then the files are followed.
