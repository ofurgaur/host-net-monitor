use crate::enrichment::{Enricher, GeoInfo};
use crate::flow::{Record, aggregate_by_ip};
use crate::reputation::ReputationReader;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::Path,
};

pub fn check_output(path: &Path) -> Result<()> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening output {}", path.display()))?;
    Ok(())
}

pub fn check_outputs(path: &Path, ip_path: &Path) -> Result<()> {
    check_output(path)?;
    check_output(ip_path)?;
    ensure!(
        path.canonicalize()? != ip_path.canonicalize()?,
        "output paths resolve to the same file"
    );
    Ok(())
}

pub fn append_window(path: &Path, ip_path: &Path, records: &[Record]) -> Result<()> {
    append_enriched_window_with_reputation(path, ip_path, records, None, None)
}

#[derive(Serialize)]
struct Enriched<'a, T> {
    #[serde(flatten)]
    record: &'a T,
    #[serde(skip_serializing_if = "Option::is_none")]
    geo: Option<&'a GeoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reputation: Option<&'a serde_json::Value>,
}

pub fn append_enriched_window(
    path: &Path,
    ip_path: &Path,
    records: &[Record],
    enricher: Option<&Enricher>,
) -> Result<()> {
    append_enriched_window_with_reputation(path, ip_path, records, enricher, None)
}

pub fn append_enriched_window_with_reputation(
    path: &Path,
    ip_path: &Path,
    records: &[Record],
    enricher: Option<&Enricher>,
    reputation: Option<&ReputationReader>,
) -> Result<()> {
    let ip_records = aggregate_by_ip(records);
    if enricher.is_none() && reputation.is_none() {
        append(path, records).context("writing endpoint log")?;
        return append(ip_path, &ip_records).context("writing per-IP log");
    }
    // One lookup per unique IP, bounded by this window's flow limit. No persistent cache.
    let mut geo = HashMap::new();
    for record in &ip_records {
        geo.insert(
            record.external_ip,
            match enricher {
                Some(reader) => reader.lookup(record.external_ip)?,
                None => None,
            },
        );
    }
    let mut reputation_data = HashMap::new();
    for record in &ip_records {
        reputation_data.insert(
            record.external_ip,
            match reputation {
                Some(reader) => reader.lookup(record.external_ip)?,
                None => None,
            },
        );
    }
    let detailed: Vec<_> = records
        .iter()
        .map(|record| Enriched {
            record,
            geo: geo.get(&record.external_ip).and_then(Option::as_ref),
            reputation: reputation_data
                .get(&record.external_ip)
                .and_then(Option::as_ref),
        })
        .collect();
    let summary: Vec<_> = ip_records
        .iter()
        .map(|record| Enriched {
            record,
            geo: geo.get(&record.external_ip).and_then(Option::as_ref),
            reputation: reputation_data
                .get(&record.external_ip)
                .and_then(Option::as_ref),
        })
        .collect();
    append(path, &detailed).context("writing endpoint log")?;
    append(ip_path, &summary).context("writing per-IP log")
}

pub fn write_records<T: Serialize>(mut writer: impl Write, records: &[T]) -> Result<()> {
    for record in records {
        serde_json::to_writer(&mut writer, record)?;
        writer.write_all(b"\n")?;
    }
    writer.flush().context("flushing JSONL output")
}

/// Reopen on each window, allowing rename/create log rotation.
pub fn append<T: Serialize>(path: &Path, records: &[T]) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening output {}", path.display()))?;
    write_records(BufWriter::new(file), records)
}
