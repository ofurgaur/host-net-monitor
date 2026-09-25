use chrono::{TimeZone, Utc};
use host_net_monitor::{
    config::Config,
    flow::{Accounted, Aggregator},
    output,
    packet::{self, PacketEvent, Protocol, Skip},
    runtime::Windows,
};
use std::{
    collections::HashSet,
    io::{self, Write},
    net::IpAddr,
    time::{Duration, Instant},
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
fn locals() -> HashSet<IpAddr> {
    [ip("192.168.1.20"), ip("2001:db8::1")].into()
}
fn config() -> Config {
    serde_yaml::from_str(include_str!("../config.example.yaml")).unwrap()
}
fn aggregator(limit: usize) -> Aggregator {
    Aggregator::new(locals(), config().exclusions(), limit)
}
fn time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 24, 12, 0, 30).unwrap()
}
fn event() -> PacketEvent {
    PacketEvent {
        protocol: Protocol::Tcp,
        src_ip: ip("192.168.1.20"),
        dst_ip: ip("1.1.1.1"),
        src_port: 55001,
        dst_port: 443,
        ip_length: 100,
    }
}
fn reverse(p: PacketEvent) -> PacketEvent {
    PacketEvent {
        src_ip: p.dst_ip,
        dst_ip: p.src_ip,
        src_port: p.dst_port,
        dst_port: p.src_port,
        ..p
    }
}
fn ipv4(tcp: bool, payload: usize) -> Vec<u8> {
    let transport = if tcp { 20 } else { 8 };
    let total = 20 + transport + payload;
    let mut b = vec![0u8; total];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    b[9] = if tcp { 6 } else { 17 };
    b[12..16].copy_from_slice(&[192, 168, 1, 20]);
    b[16..20].copy_from_slice(&[1, 1, 1, 1]);
    b[20..22].copy_from_slice(&55001u16.to_be_bytes());
    b[22..24].copy_from_slice(&443u16.to_be_bytes());
    if tcp {
        b[32] = 0x50;
    } else {
        b[24..26].copy_from_slice(&((transport + payload) as u16).to_be_bytes());
    }
    b
}
fn ipv6(extension: bool) -> Vec<u8> {
    let extra = if extension { 8 } else { 0 };
    let mut b = vec![0u8; 48 + extra];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&((8 + extra) as u16).to_be_bytes());
    b[6] = if extension { 0 } else { 17 };
    b[8..24].copy_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    b[24..40].copy_from_slice(
        &"2606:4700:4700::1111"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    if extension {
        b[40] = 17;
    }
    let t = 40 + extra;
    b[t..t + 2].copy_from_slice(&12345u16.to_be_bytes());
    b[t + 2..t + 4].copy_from_slice(&53u16.to_be_bytes());
    b[t + 4..t + 6].copy_from_slice(&8u16.to_be_bytes());
    b
}

#[test]
fn direction_and_unique_flows() {
    let mut a = aggregator(100);
    for _ in 0..10 {
        assert_eq!(a.observe(event()), Accounted::Counted);
    }
    a.observe(reverse(event()));
    a.observe(PacketEvent {
        src_port: 55002,
        ..event()
    });
    let r = a.flush(time());
    assert_eq!(r.len(), 1);
    assert_eq!(
        (
            r[0].external_ip,
            r[0].external_port,
            r[0].flow_count,
            r[0].flow_byte_sum
        ),
        (ip("1.1.1.1"), 443, 2, 1200)
    );
    assert!(a.flush(time()).is_empty());
    a.observe(event());
    assert_eq!(a.flush(time())[0].flow_count, 1);
}

#[test]
fn incoming_remote_port_is_not_local_service_port() {
    let mut a = aggregator(100);
    a.observe(PacketEvent {
        src_ip: ip("8.8.8.8"),
        dst_ip: ip("192.168.1.20"),
        src_port: 52000,
        dst_port: 443,
        ..event()
    });
    let r = a.flush(time());
    assert_eq!(r[0].external_port, 52000);
}

#[test]
fn ownership_and_exclusions() {
    let mut a = aggregator(100);
    for remote in [
        "192.168.1.50",
        "10.2.3.4",
        "172.31.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ] {
        assert_eq!(
            a.observe(PacketEvent {
                dst_ip: ip(remote),
                ..event()
            }),
            Accounted::Ignored
        );
    }
    assert_eq!(
        a.observe(PacketEvent {
            src_ip: ip("192.168.1.50"),
            ..event()
        }),
        Accounted::Ignored
    );
    assert_eq!(
        a.observe(PacketEvent {
            dst_ip: ip("192.168.1.20"),
            ..event()
        }),
        Accounted::Ignored
    );
    a.replace_local(HashSet::new());
    assert_eq!(a.observe(event()), Accounted::Ignored);
}

#[test]
fn custom_public_cidr_and_protocol_buckets() {
    let mut a = Aggregator::new(locals(), vec!["1.1.1.0/24".parse().unwrap()], 100);
    assert_eq!(a.observe(event()), Accounted::Ignored);
    let mut a = aggregator(100);
    a.observe(event());
    a.observe(PacketEvent {
        protocol: Protocol::Udp,
        ..event()
    });
    assert_eq!(a.flush(time()).len(), 2);
}

#[test]
fn capacity_preserves_existing_flows() {
    let mut a = aggregator(1);
    a.observe(event());
    assert_eq!(
        a.observe(PacketEvent {
            src_port: 55002,
            ..event()
        }),
        Accounted::CapacityExceeded
    );
    assert_eq!(a.observe(event()), Accounted::Counted);
    let r = a.flush(time());
    assert_eq!((r[0].flow_count, r[0].flow_byte_sum), (1, 200));
    assert_eq!(
        a.observe(PacketEvent {
            src_port: 55002,
            ..event()
        }),
        Accounted::Counted
    );
}

#[test]
fn ipv4_tcp_udp_and_truncated_payload() {
    for tcp in [true, false] {
        let b = ipv4(tcp, 300);
        let headers = if tcp { 40 } else { 28 };
        let p = packet::parse(&b[..headers], b.len() as u32, 101).unwrap();
        assert_eq!(p.ip_length, b.len() as u32);
        assert_eq!((p.src_port, p.dst_port), (55001, 443));
        assert_eq!(p.protocol, if tcp { Protocol::Tcp } else { Protocol::Udp });
    }
}

#[test]
fn ipv6_with_and_without_extension() {
    for extension in [true, false] {
        let b = ipv6(extension);
        let p = packet::parse(&b, b.len() as u32, 101).unwrap();
        assert_eq!(p.protocol, Protocol::Udp);
        assert_eq!(p.ip_length, b.len() as u32);
        let mut a = aggregator(10);
        a.observe(p);
        a.observe(reverse(p));
        let records = a.flush(time());
        assert_eq!(records[0].flow_count, 1);
        assert_eq!(records[0].flow_byte_sum, b.len() as u64 * 2);
    }
}

#[test]
fn link_layers_exclude_framing_bytes() {
    let ip = ipv4(true, 0);
    for (link, size, proto_at) in [(1, 14, 12), (113, 16, 14), (276, 20, 0)] {
        let mut frame = vec![0; size];
        frame[proto_at..proto_at + 2].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend(&ip);
        assert_eq!(
            packet::parse(&frame, frame.len() as u32, link)
                .unwrap()
                .ip_length,
            40
        );
    }
    for link in [0, 108] {
        let mut frame = vec![0; 4];
        frame.extend(&ip);
        assert_eq!(
            packet::parse(&frame, frame.len() as u32, link)
                .unwrap()
                .ip_length,
            40
        );
    }
    let mut vlan = vec![0; 22];
    vlan[12..14].copy_from_slice(&0x88a8u16.to_be_bytes());
    vlan[16..18].copy_from_slice(&0x8100u16.to_be_bytes());
    vlan[20..22].copy_from_slice(&0x0800u16.to_be_bytes());
    vlan.extend(ip);
    assert_eq!(
        packet::parse(&vlan, vlan.len() as u32, 1)
            .unwrap()
            .ip_length,
        40
    );
}

#[test]
fn fragments_and_malformed_packets_are_rejected() {
    let mut v4 = ipv4(true, 0);
    for field in [0x2000u16, 1] {
        v4[6..8].copy_from_slice(&field.to_be_bytes());
        assert_eq!(packet::parse(&v4, 40, 101).unwrap_err(), Skip::Fragmented);
    }
    let mut v6 = ipv6(true);
    v6[6] = 44;
    assert_eq!(
        packet::parse(&v6, v6.len() as u32, 101).unwrap_err(),
        Skip::Fragmented
    );
    let b = ipv4(true, 0);
    for cut in 0..b.len() {
        assert!(packet::parse(&b[..cut], b.len() as u32, 101).is_err());
    }
    let mut b = ipv4(true, 0);
    b[32] = 0x40;
    assert_eq!(packet::parse(&b, 40, 101).unwrap_err(), Skip::Malformed);
    let b = ipv4(false, 0);
    assert_eq!(packet::parse(&b, 27, 101).unwrap_err(), Skip::Malformed);
    let mut b = ipv4(false, 0);
    b[24..26].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(packet::parse(&b, 28, 101).unwrap_err(), Skip::Malformed);
}

#[test]
fn arbitrary_input_never_panics() {
    let mut seed = 123456789u64;
    for len in 0..600 {
        let b: Vec<_> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        for link in [0, 1, 12, 101, 108, 113, 228, 229, 276, 999] {
            let _ = packet::parse(&b, len as u32, link);
        }
    }
}

#[test]
fn interval_boundaries_and_idle_gaps() {
    let start = Utc.with_ymd_and_hms(2026, 9, 24, 12, 0, 7).unwrap();
    let mono = Instant::now();
    let mut w = Windows::new(start, mono, 30);
    assert_eq!(w.due(mono + Duration::from_secs(22)), None);
    assert_eq!(w.due(mono + Duration::from_secs(23)), Some(time()));
    assert_eq!(w.due(mono + Duration::from_secs(23)), None);
    assert_eq!(
        w.due(mono + Duration::from_secs(113)),
        Some(time() + chrono::Duration::seconds(30))
    );
    assert_eq!(w.due(mono + Duration::from_secs(113)), None);
    assert_eq!(
        w.due(mono + Duration::from_secs(143)),
        Some(time() + chrono::Duration::seconds(120))
    );
}

#[test]
fn jsonl_append_and_error_propagation() {
    let mut a = aggregator(10);
    a.observe(event());
    let records = a.flush(time());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flows.jsonl");
    output::append(&path, &records).unwrap();
    output::append(&path, &records).unwrap();
    let contents = std::fs::read_to_string(path).unwrap();
    assert_eq!(contents.lines().count(), 2);
    for line in contents.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["timestamp"], "2026-09-24T12:00:30Z");
        assert_eq!(value["protocol"], "tcp");
        assert_eq!(value.as_object().unwrap().len(), 6);
    }
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("disk full"))
        }
    }
    assert!(output::write_records(Broken, &records).is_err());
    assert!(output::append(dir.path(), &records).is_err());
}

#[test]
fn config_validation_and_defaults() {
    let mut c = config();
    c.validate().unwrap();
    assert!(c.exclusions().iter().any(|n| n.contains(&ip("ff02::1"))));
    c.capture.interfaces.clear();
    assert!(c.validate().is_err());
    c.capture.interfaces.push("any".into());
    assert!(c.validate().is_err());
    c.capture.interfaces[0] = "eth0".into();
    c.aggregation.max_flows = 0;
    assert!(c.validate().is_err());
    assert!(serde_yaml::from_str::<Config>("unexpected: true").is_err());
}

#[test]
fn native_pcap_replay_to_jsonl() {
    // This file contains synthetic headers only, never live payloads.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("headers.pcap");
    let dead = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let template = dir.path().join("empty.pcap");
    drop(dead.savefile(&template).unwrap());
    let mut bytes = std::fs::read(template).unwrap();
    // Native-endian classic pcap records, matching libpcap's global header.
    for ip in [ipv4(true, 0), ipv4(true, 0), ipv6(true)] {
        let mut frame = vec![0u8; 14];
        let ethertype: u16 = if ip[0] >> 4 == 4 { 0x0800 } else { 0x86dd };
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame.extend(ip);
        for value in [1u32, 0, frame.len() as u32, frame.len() as u32] {
            bytes.extend_from_slice(&value.to_ne_bytes());
        }
        bytes.extend(frame);
    }
    std::fs::write(&path, bytes).unwrap();
    let mut capture = pcap::Capture::from_file(path).unwrap();
    let link = capture.get_datalink().0;
    let mut a = aggregator(100);
    let mut packets = 0;
    loop {
        match capture.next_packet() {
            Ok(p) => {
                a.observe(packet::parse(p.data, p.header.len, link).unwrap());
                packets += 1;
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => panic!("unexpected replay failure: {e}"),
        }
    }
    assert_eq!(packets, 3);
    let records = a.flush(time());
    let mut json = Vec::new();
    output::write_records(&mut json, &records).unwrap();
    let values: Vec<serde_json::Value> = std::str::from_utf8(&json)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0]["flow_count"], 1);
    assert_eq!(values[0]["flow_byte_sum"], 80);
    assert_eq!(values[1]["flow_byte_sum"], 56);
}

#[test]
fn repeated_load_respects_flow_limit_and_resets_each_window() {
    let mut a = aggregator(1000);
    for _ in 0..5 {
        let mut dropped = 0;
        for sequence in 0..100_000u32 {
            let p = PacketEvent {
                src_port: (sequence % 2000) as u16 + 10000,
                ..event()
            };
            if a.observe(p) == Accounted::CapacityExceeded {
                dropped += 1;
            }
        }
        assert_eq!(dropped, 50_000);
        let records = a.flush(time());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].flow_count, 1000);
        assert_eq!(records[0].flow_byte_sum, 5_000_000);
    }
}

#[test]
fn ipv6_tcp_and_ipv4_options() {
    let mut b = ipv6(false);
    b.resize(60, 0);
    b[4..6].copy_from_slice(&20u16.to_be_bytes());
    b[6] = 6;
    b[52] = 0x50;
    assert_eq!(packet::parse(&b, 60, 101).unwrap().protocol, Protocol::Tcp);

    let mut b = ipv4(true, 0);
    b.splice(20..20, [1, 1, 1, 1]);
    b[0] = 0x46;
    b[2..4].copy_from_slice(&44u16.to_be_bytes());
    let p = packet::parse(&b, 44, 101).unwrap();
    assert_eq!(p.src_port, 55001);
    assert_eq!(p.ip_length, 44);
}

#[test]
fn per_ip_log_combines_ports_protocols_and_directions() {
    let mut a = aggregator(100);
    a.observe(event());
    a.observe(reverse(event()));
    a.observe(PacketEvent {
        dst_port: 80,
        ..event()
    });
    a.observe(PacketEvent {
        protocol: Protocol::Udp,
        ..event()
    });
    a.observe(PacketEvent {
        src_port: 55002,
        ..event()
    });
    a.observe(PacketEvent {
        dst_ip: ip("8.8.8.8"),
        ..event()
    });
    let ipv6 = ipv6(false);
    a.observe(packet::parse(&ipv6, ipv6.len() as u32, 101).unwrap());
    let records = a.flush(time());
    let dir = tempfile::tempdir().unwrap();
    let detailed = dir.path().join("flows.jsonl");
    let summary = dir.path().join("ips.jsonl");
    output::check_outputs(&detailed, &summary).unwrap();
    output::append_window(&detailed, &summary, &records).unwrap();
    assert_eq!(
        std::fs::read_to_string(&detailed).unwrap().lines().count(),
        5
    );
    let text = std::fs::read_to_string(&summary).unwrap();
    let values: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(values.len(), 3);
    assert_eq!(
        values[0],
        serde_json::json!({
            "timestamp": "2026-09-24T12:00:30Z", "external_ip": "1.1.1.1",
            "flow_count": 4, "flow_byte_sum": 500
        })
    );
    assert_eq!(values[1]["flow_byte_sum"], 100);
    assert_eq!(values[2]["flow_byte_sum"], 48);
    // Empty windows add no lines; subsequent windows append and reset flow counts.
    output::append_window(&detailed, &summary, &a.flush(time())).unwrap();
    a.observe(event());
    let next = time() + chrono::Duration::seconds(30);
    output::append_window(&detailed, &summary, &a.flush(next)).unwrap();
    let text = std::fs::read_to_string(&summary).unwrap();
    let values: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(values.len(), 4);
    assert_eq!(values[3]["flow_count"], 1);
    assert_eq!(values[3]["timestamp"], "2026-09-24T12:01:00Z");
}

#[test]
fn per_ip_output_config_defaults_and_distinct_paths() {
    let mut c = config();
    c.output.ip_path = None;
    assert_eq!(
        c.output.ip_path(),
        std::path::PathBuf::from("./network-flows.by-ip.jsonl")
    );
    c.validate().unwrap();
    c.output.ip_path = Some(c.output.path.clone());
    assert!(c.validate().is_err());
    c.output.ip_path = Some("".into());
    assert!(c.validate().is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flows.jsonl");
    assert!(output::check_outputs(&path, &dir.path().join("./flows.jsonl")).is_err());
}

#[test]
fn per_ip_write_failure_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = aggregator(10);
    a.observe(event());
    let error = output::append_window(
        &dir.path().join("flows.jsonl"),
        dir.path(),
        &a.flush(time()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("per-IP log"));
}

#[test]
fn enrichment_disabled_does_not_require_database() {
    use host_net_monitor::{config::EnrichmentConfig, enrichment::Enricher};
    let config = EnrichmentConfig {
        enabled: false,
        database_path: "/does-not-exist.mmdb".into(),
    };
    assert!(Enricher::open(&config).unwrap().is_none());
}

#[test]
fn enrichment_reports_missing_and_invalid_database() {
    use host_net_monitor::{config::EnrichmentConfig, enrichment::Enricher};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.mmdb");
    let config = EnrichmentConfig {
        enabled: true,
        database_path: path.clone(),
    };
    assert!(Enricher::open(&config).is_err());
    std::fs::write(path, b"not an MMDB").unwrap();
    assert!(Enricher::open(&config).is_err());
}

#[test]
fn enrichment_config_resolves_database_relative_to_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, include_str!("../config.example.yaml")).unwrap();
    let mut c = Config::load(&path).unwrap();
    assert_eq!(
        c.enrichment.database_path,
        dir.path().join("mmdb/IP2LOCATION-LITE-DB11.MMDB")
    );
    c.enrichment.enabled = true;
    c.enrichment.database_path = "".into();
    assert!(c.validate().is_err());
    let omitted = include_str!("../config.example.yaml")
        .split("enrichment:")
        .next()
        .unwrap();
    let c: Config = serde_yaml::from_str(omitted).unwrap();
    assert!(!c.enrichment.enabled);
}

#[test]
#[ignore = "requires the user-provided IP2Location MMDB; run explicitly for local integration validation"]
fn supplied_mmdb_enriches_both_logs_without_changing_totals() {
    use host_net_monitor::{config::EnrichmentConfig, enrichment::Enricher};
    let config = EnrichmentConfig {
        enabled: true,
        database_path: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("mmdb/IP2LOCATION-LITE-DB11.MMDB"),
    };
    let enricher = Enricher::open(&config).unwrap().unwrap();
    let geo = enricher.lookup(ip("8.8.8.8")).unwrap().unwrap();
    assert_eq!(geo.country_code.as_deref(), Some("US"));
    assert!(geo.city_name.is_some());
    assert!(geo.region_name.is_some());
    assert!(geo.latitude.is_some());
    assert!(geo.longitude.is_some());
    assert!(geo.postal_code.is_some());
    assert!(geo.time_zone.is_some());
    assert!(enricher.lookup(ip("192.168.1.1")).unwrap().is_none());
    assert!(
        enricher
            .lookup(ip("2606:4700:4700::1111"))
            .unwrap()
            .is_some()
    );
    let mut a = aggregator(10);
    a.observe(event());
    a.observe(reverse(event()));
    a.observe(PacketEvent {
        dst_port: 80,
        ..event()
    });
    a.observe(PacketEvent {
        dst_ip: ip("2606:4700:4700::1111"),
        ..event()
    });
    let records = a.flush(time());
    let dir = tempfile::tempdir().unwrap();
    let detailed = dir.path().join("flows.jsonl");
    let summary = dir.path().join("ips.jsonl");
    output::append_enriched_window(&detailed, &summary, &records, Some(&enricher)).unwrap();
    for (path, expected) in [
        (&detailed, serde_json::to_value(&records).unwrap()),
        (
            &summary,
            serde_json::to_value(host_net_monitor::flow::aggregate_by_ip(&records)).unwrap(),
        ),
    ] {
        let text = std::fs::read_to_string(path).unwrap();
        let actual: Vec<serde_json::Value> = text
            .lines()
            .map(|line| {
                let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
                let geo = value.as_object_mut().unwrap().remove("geo").unwrap();
                assert!(geo["country_code"].is_string());
                value
            })
            .collect();
        assert_eq!(serde_json::to_value(actual).unwrap(), expected);
    }
}

#[test]
fn macos_loopback_and_vpn_framing_support_both_ip_versions() {
    for payload in [ipv4(true, 0), ipv4(false, 0), ipv6(true)] {
        let family: u32 = if payload[0] >> 4 == 4 { 2 } else { 30 };
        for (link, header) in [(0, family.to_ne_bytes()), (108, family.to_be_bytes())] {
            let mut frame = header.to_vec();
            frame.extend_from_slice(&payload);
            let parsed = packet::parse(&frame, frame.len() as u32, link).unwrap();
            assert_eq!(parsed.ip_length, payload.len() as u32);
            let mut a = aggregator(10);
            assert_eq!(a.observe(parsed), Accounted::Counted);
            assert_eq!(a.observe(reverse(parsed)), Accounted::Counted);
            let rows = a.flush(time());
            assert_eq!(rows[0].flow_count, 1);
            assert_eq!(rows[0].flow_byte_sum, 2 * payload.len() as u64);
        }
        let parsed = packet::parse(&payload, payload.len() as u32, 12).unwrap();
        assert_eq!(parsed.ip_length, payload.len() as u32);
    }
}

#[test]
fn macos_example_configuration_is_valid() {
    let c: Config = serde_yaml::from_str(include_str!("../config.macos.example.yaml")).unwrap();
    c.validate().unwrap();
    assert_eq!(c.capture.interfaces, ["en0"]);
    assert!(!c.enrichment.enabled);
    assert!(c.output.path.is_absolute());
    assert!(c.output.ip_path().is_absolute());
}

#[test]
fn threat_reputation_can_be_enabled_and_is_added_to_both_logs() {
    use host_net_monitor::{config::ReputationConfig, reputation::ReputationReader};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("mmdb/threat-reputation.mmdb");
    let reader = ReputationReader::open(&ReputationConfig {
        enabled: true,
        database_path: path,
    })
    .unwrap()
    .unwrap();
    let match_data = reader.lookup(ip("50.16.16.211")).unwrap().unwrap();
    assert_eq!(match_data["schema_version"], 1);
    assert!(match_data["matches"].as_array().unwrap().len() >= 2);
    assert!(reader.lookup(ip("8.8.8.8")).unwrap().is_none());

    let mut a = aggregator(10);
    a.observe(event());
    let records = a.flush(time());
    let dir = tempfile::tempdir().unwrap();
    let detailed = dir.path().join("flows.jsonl");
    let summary = dir.path().join("ips.jsonl");
    output::append_enriched_window_with_reputation(
        &detailed,
        &summary,
        &records,
        None,
        Some(&reader),
    )
    .unwrap();
    for path in [detailed, summary] {
        let value: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert!(value.get("reputation").is_none()); // 1.1.1.1 is not in the generated feed.
    }
    let hit = host_net_monitor::flow::Record {
        timestamp: time(),
        external_ip: ip("50.16.16.211"),
        external_port: 443,
        protocol: Protocol::Tcp,
        flow_count: 1,
        flow_byte_sum: 100,
    };
    output::append_enriched_window_with_reputation(
        &dir.path().join("hit.jsonl"),
        &dir.path().join("hit-ip.jsonl"),
        &[hit],
        None,
        Some(&reader),
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(dir.path().join("hit.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert!(value["reputation"]["matches"].as_array().unwrap().len() >= 2);
}
