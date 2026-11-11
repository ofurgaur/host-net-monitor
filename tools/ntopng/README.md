# ntopng exporter

`export.py` converts the monitor's JSONL records to NetFlow v5 over UDP. Use it with ntopng's native NetFlow collector or with nProbe.

```sh
python3 tools/ntopng/export.py \
  --input network-flows.jsonl \
  --input network-ips.jsonl \
  --target 127.0.0.1:2055 \
  --local-ip 192.168.1.20 \
  --chunk-size 30 \
  --interval 1
```

For nProbe:

```sh
nprobe --collector-port 2055 -i none -n none \
  --zmq tcp://127.0.0.1:5556 -T "@NTOPNG@"
ntopng -i "tcp://*:5556c"
```

The exporter maps `flow_count` to NetFlow packet count and `flow_byte_sum` to octet count. IPv6 records are skipped because NetFlow v5 is IPv4-only; use an IPFIX exporter for mixed IPv4/IPv6 data. The JSONL format does not preserve the original local endpoint direction, so `--local-ip` is used as the source address for exported records.

## Minimal ZeroMQ exporter

This exporter publishes the ntopng flow message format over ZeroMQ PUB. Start it after ntopng has connected as a subscriber:

```sh
python3 -m pip install -r tools/ntopng/requirements.txt
python3 tools/ntopng/zmq_export.py \
  --input network-flows.jsonl \
  --connect tcp://127.0.0.1:5556 \
  --local-ip 192.168.1.20 \
  --interval 1 \
  --since-hours 24
```

Configure ntopng as the ZeroMQ collector, for example `ntopng -i zmq://127.0.0.1:5556c`. The exporter connects to ntopng; it does not bind the collector endpoint. Use `--bind` only when running the reverse topology where ntopng connects to the exporter. The exporter sends one `flow` topic message per JSONL row, with a little-endian `zmq_msg_hdr_v1` header and a JSON array payload. IPv6 rows are skipped by this minimal IPv4 format.

`--since-hours 24` replays only records from the last day. The original JSONL timestamp is retained in `FIRST_SWITCHED` and `LAST_SWITCHED`; `--interval` controls how quickly records are delivered.
