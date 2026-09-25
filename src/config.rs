use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub capture: CaptureConfig,
    #[serde(default)]
    pub aggregation: AggregationConfig,
    /// Additional exclusions; defaults are always retained.
    #[serde(default)]
    pub ignored_networks: Vec<IpNet>,
    pub output: OutputConfig,
    #[serde(default)]
    pub enrichment: EnrichmentConfig,
    #[serde(default)]
    pub reputation: ReputationConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnrichmentConfig {
    pub enabled: bool,
    pub database_path: PathBuf,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: "mmdb/IP2LOCATION-LITE-DB11.MMDB".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReputationConfig {
    pub enabled: bool,
    pub database_path: PathBuf,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: "mmdb/threat-reputation.mmdb".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub promiscuous: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AggregationConfig {
    pub interval_seconds: u64,
    pub max_flows: usize,
    pub event_queue_capacity: usize,
    pub output_queue_capacity: usize,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 30,
            max_flows: 100_000,
            event_queue_capacity: 8192,
            output_queue_capacity: 4,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: PathBuf,
    /// Per-IP totals; defaults to the detailed path with a `.by-ip.jsonl` extension.
    #[serde(default)]
    pub ip_path: Option<PathBuf>,
}

impl OutputConfig {
    pub fn ip_path(&self) -> PathBuf {
        self.ip_path
            .clone()
            .unwrap_or_else(|| self.path.with_extension("by-ip.jsonl"))
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = serde_yaml::from_str(
            &fs::read_to_string(path)
                .with_context(|| format!("reading configuration {}", path.display()))?,
        )
        .context("invalid YAML configuration")?;
        config.validate()?;
        if config.enrichment.database_path.is_relative() {
            config.enrichment.database_path = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(&config.enrichment.database_path);
        }
        if config.reputation.database_path.is_relative() {
            config.reputation.database_path = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(&config.reputation.database_path);
        }
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.enrichment.enabled || !self.enrichment.database_path.as_os_str().is_empty(),
            "enrichment.database_path must not be empty when enrichment is enabled"
        );
        ensure!(
            !self.reputation.enabled || !self.reputation.database_path.as_os_str().is_empty(),
            "reputation.database_path must not be empty when reputation is enabled"
        );
        ensure!(
            self.capture.interfaces.len() == 1,
            "monitor requires exactly one explicit capture interface"
        );
        let name = &self.capture.interfaces[0];
        ensure!(
            !name.trim().is_empty() && name != "any",
            "select a named interface, not the aggregate 'any' device"
        );
        ensure!(
            (1..=3600).contains(&self.aggregation.interval_seconds),
            "interval_seconds must be 1..=3600"
        );
        ensure!(
            (1..=1_000_000).contains(&self.aggregation.max_flows),
            "max_flows must be 1..=1000000"
        );
        ensure!(
            (1..=1_000_000).contains(&self.aggregation.event_queue_capacity),
            "event_queue_capacity must be 1..=1000000"
        );
        ensure!(
            (1..=64).contains(&self.aggregation.output_queue_capacity),
            "output_queue_capacity must be 1..=64"
        );
        ensure!(
            self.output.kind == "jsonl",
            "only jsonl output is supported"
        );
        ensure!(
            !self.output.path.as_os_str().is_empty(),
            "output path must not be empty"
        );
        let ip_path = self.output.ip_path();
        ensure!(
            !ip_path.as_os_str().is_empty(),
            "output ip_path must not be empty"
        );
        ensure!(
            ip_path != self.output.path,
            "output path and ip_path must be different"
        );
        Ok(())
    }

    pub fn exclusions(&self) -> Vec<IpNet> {
        let mut nets: Vec<IpNet> = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ]
        .iter()
        .map(|s| s.parse().expect("constant CIDR"))
        .collect();
        nets.extend(self.ignored_networks.iter().copied());
        nets
    }
}
