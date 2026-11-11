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
