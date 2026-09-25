use crate::packet::{PacketEvent, Protocol};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub protocol: Protocol,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub external_ip: IpAddr,
    pub external_port: u16,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct AggregateKey {
    external_ip: IpAddr,
    external_port: u16,
    protocol: Protocol,
}

#[derive(Debug, Serialize)]
pub struct Record {
    pub timestamp: DateTime<Utc>,
    pub external_ip: IpAddr,
    pub external_port: u16,
    pub protocol: Protocol,
    pub flow_count: u64,
    pub flow_byte_sum: u64,
}

#[derive(Debug, Serialize)]
pub struct IpRecord {
    pub timestamp: DateTime<Utc>,
    pub external_ip: IpAddr,
    pub flow_count: u64,
    pub flow_byte_sum: u64,
}

/// Endpoint/protocol buckets contain disjoint five-tuples, so their counts add.
pub fn aggregate_by_ip(records: &[Record]) -> Vec<IpRecord> {
    let mut totals = BTreeMap::new();
    for record in records {
        let (count, bytes) = totals
            .entry((record.timestamp, record.external_ip))
            .or_insert((0, 0));
        *count += record.flow_count;
        *bytes += record.flow_byte_sum;
    }
    totals
        .into_iter()
        .map(
            |((timestamp, external_ip), (flow_count, flow_byte_sum))| IpRecord {
                timestamp,
                external_ip,
                flow_count,
                flow_byte_sum,
            },
        )
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Accounted {
    Counted,
    Ignored,
    CapacityExceeded,
}

pub struct Aggregator {
    local: HashSet<IpAddr>,
    ignored_networks: Vec<IpNet>,
    max_flows: usize,
    flows: HashSet<FlowKey>,
    buckets: HashMap<AggregateKey, (u64, u64)>,
}

impl Aggregator {
    pub fn new(local: HashSet<IpAddr>, ignored_networks: Vec<IpNet>, max_flows: usize) -> Self {
        Self {
            local,
            ignored_networks,
            max_flows,
            flows: HashSet::new(),
            buckets: HashMap::new(),
        }
    }
    pub fn replace_local(&mut self, local: HashSet<IpAddr>) {
        self.local = local;
    }
    pub fn observe(&mut self, p: PacketEvent) -> Accounted {
        let src_local = self.local.contains(&p.src_ip);
        let dst_local = self.local.contains(&p.dst_ip);
        if src_local == dst_local {
            return Accounted::Ignored;
        }
        let (local_ip, local_port, external_ip, external_port) = if src_local {
            (p.src_ip, p.src_port, p.dst_ip, p.dst_port)
        } else {
            (p.dst_ip, p.dst_port, p.src_ip, p.src_port)
        };
        if self
            .ignored_networks
            .iter()
            .any(|n| n.contains(&external_ip))
        {
            return Accounted::Ignored;
        }
        let flow = FlowKey {
            protocol: p.protocol,
            local_ip,
            local_port,
            external_ip,
            external_port,
        };
        let existing = self.flows.contains(&flow);
        if !existing && self.flows.len() >= self.max_flows {
            return Accounted::CapacityExceeded;
        }
        self.flows.insert(flow);
        let bucket = self
            .buckets
            .entry(AggregateKey {
                external_ip,
                external_port,
                protocol: p.protocol,
            })
            .or_default();
        bucket.0 += u64::from(!existing);
        bucket.1 += p.ip_length as u64;
        Accounted::Counted
    }
    pub fn flush(&mut self, timestamp: DateTime<Utc>) -> Vec<Record> {
        self.flows.clear();
        let mut buckets: Vec<_> = self.buckets.drain().collect();
        buckets.sort_unstable_by_key(|(k, _)| *k);
        buckets
            .into_iter()
            .map(|(k, (count, bytes))| Record {
                timestamp,
                external_ip: k.external_ip,
                external_port: k.external_port,
                protocol: k.protocol,
                flow_count: count,
                flow_byte_sum: bytes,
            })
            .collect()
    }
}
