use crate::config::ReputationConfig;
use anyhow::{Context, Result, ensure};
use maxminddb::Reader;
use serde_json::Value;
use std::net::IpAddr;

pub struct ReputationReader {
    reader: Reader<Vec<u8>>,
}

impl ReputationReader {
    pub fn open(config: &ReputationConfig) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let reader = Reader::open_readfile(&config.database_path).with_context(|| {
            format!(
                "opening reputation database {}",
                config.database_path.display()
            )
        })?;
        ensure!(
            reader.metadata().database_type == "HostNetMonitor-Threat-Reputation",
            "reputation database has an unsupported database_type; build it with tools/reputation/update.py"
        );
        Ok(Some(Self { reader }))
    }

    pub fn lookup(&self, ip: IpAddr) -> Result<Option<Value>> {
        let result = self
            .reader
            .lookup(ip)
            .with_context(|| format!("reputation lookup for {ip}"))?;
        result
            .decode::<Value>()
            .with_context(|| format!("decoding reputation entry for {ip}"))
    }
}
