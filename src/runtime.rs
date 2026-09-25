use crate::{
    capture::{self, CaptureSource, Read},
    config::Config,
    flow::{Accounted, Aggregator, Record},
    output,
    packet::{PacketEvent, Skip},
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

enum Event {
    Packet(PacketEvent),
    Boundary(DateTime<Utc>),
    Addresses(HashSet<IpAddr>),
}

/// UTC alignment at startup, advanced with a monotonic clock to resist NTP jumps.
pub struct Windows {
    end: DateTime<Utc>,
    deadline: Instant,
    interval: Duration,
}
impl Windows {
    pub fn new(now: DateTime<Utc>, mono: Instant, seconds: u64) -> Self {
        assert!(seconds > 0 && seconds <= 3600);
        let end_seconds = (now.timestamp().div_euclid(seconds as i64) + 1) * seconds as i64;
        let end = DateTime::from_timestamp(end_seconds, 0).expect("valid current time");
        Self {
            end,
            deadline: mono + (end - now).to_std().unwrap(),
            interval: Duration::from_secs(seconds),
        }
    }
    pub fn due(&mut self, now: Instant) -> Option<DateTime<Utc>> {
        if now < self.deadline {
            return None;
        }
        let end = self.end;
        // Empty elapsed windows need no records. Keep the original UTC alignment.
        let steps = now.duration_since(self.deadline).as_secs() / self.interval.as_secs() + 1;
        let advance = Duration::from_secs(self.interval.as_secs() * steps);
        self.deadline += advance;
        self.end += chrono::Duration::from_std(advance).unwrap();
        Some(end)
    }
}

#[derive(Default)]
struct Counts {
    parsed: u64,
    malformed: u64,
    unsupported: u64,
    fragmented: u64,
    queue_drops: u64,
}

fn capture_loop(
    mut source: impl CaptureSource,
    name: String,
    seconds: u64,
    tx: Sender<Event>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut windows = Windows::new(Utc::now(), Instant::now(), seconds);
    let mut refresh = Instant::now() + Duration::from_secs(30);
    let mut report = Instant::now() + Duration::from_secs(30);
    let mut counts = Counts::default();
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        // Boundaries share the FIFO with packets, so queued packets cannot cross a flush.
        if let Some(end) = windows.due(now) {
            tx.send(Event::Boundary(end))?;
        }
        if now >= refresh {
            tx.send(Event::Addresses(capture::local_addresses(&name)?))?;
            refresh = now + Duration::from_secs(30);
        }
        if now >= report {
            let (kernel_drops, interface_drops) = source.drops()?;
            tracing::info!(
                parsed = counts.parsed,
                malformed = counts.malformed,
                unsupported = counts.unsupported,
                fragmented = counts.fragmented,
                queue_drops = counts.queue_drops,
                kernel_drops,
                interface_drops,
                "capture totals; nonzero drops/skips indicate incomplete accounting"
            );
            report = now + Duration::from_secs(30);
        }
        match source.read()? {
            Read::Packet(p) => {
                counts.parsed += 1;
                match tx.try_send(Event::Packet(p)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        counts.queue_drops += 1;
                    }
                    Err(TrySendError::Disconnected(_)) => bail!("aggregation worker stopped"),
                }
            }
            Read::Skipped(Skip::Malformed) => counts.malformed += 1,
            Read::Skipped(Skip::Unsupported) => counts.unsupported += 1,
            Read::Skipped(Skip::Fragmented) => counts.fragmented += 1,
            Read::Idle => thread::sleep(Duration::from_millis(5)),
        }
    }
    let drops = source.drops();
    tracing::info!(parsed = counts.parsed, malformed = counts.malformed, unsupported = counts.unsupported,
        fragmented = counts.fragmented, queue_drops = counts.queue_drops, capture_drops = ?drops, "capture stopped");
    Ok(())
}

fn submit(tx: &Sender<Vec<Record>>, records: Vec<Record>) -> Result<()> {
    if !records.is_empty() {
        tx.try_send(records)
            .map_err(|e| anyhow!("output queue full or writer failed: {e}; accounting stopped"))?;
    }
    Ok(())
}

fn aggregate_loop(
    rx: &Receiver<Event>,
    writer: &Sender<Vec<Record>>,
    aggregator: &mut Aggregator,
) -> Result<()> {
    let mut rejected = 0u64;
    while let Ok(event) = rx.recv() {
        match event {
            Event::Packet(p) => {
                if aggregator.observe(p) == Accounted::CapacityExceeded {
                    rejected += 1;
                    if rejected == 1 {
                        tracing::warn!(
                            "flow limit exceeded; new flows are being dropped in this window"
                        );
                    }
                }
            }
            Event::Addresses(addresses) => aggregator.replace_local(addresses),
            Event::Boundary(end) => {
                if rejected != 0 {
                    tracing::warn!(
                        rejected_packets = rejected,
                        "incomplete window: flow capacity exceeded"
                    );
                }
                rejected = 0;
                submit(writer, aggregator.flush(end))?;
            }
        }
    }
    if rejected != 0 {
        tracing::warn!(rejected_packets = rejected, "incomplete final window");
    }
    let final_records = aggregator.flush(Utc::now());
    if !final_records.is_empty() {
        // Shutdown may wait for the bounded writer queue to drain.
        writer
            .send(final_records)
            .context("writing final partial window")?;
    }
    Ok(())
}

pub fn run(config: Config) -> Result<()> {
    config.validate()?;
    let enricher = crate::enrichment::Enricher::open(&config.enrichment)?;
    let reputation = crate::reputation::ReputationReader::open(&config.reputation)?;
    let name = config.capture.interfaces[0].clone();
    let local = capture::local_addresses(&name)?;
    let ip_path = config.output.ip_path();
    output::check_outputs(&config.output.path, &ip_path)?;
    let source = capture::PcapSource::open(&name, config.capture.promiscuous)?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = stop.clone();
    ctrlc::set_handler(move || signal_stop.store(true, Ordering::Relaxed))
        .context("installing shutdown handler")?;
    let (event_tx, event_rx) = bounded(config.aggregation.event_queue_capacity);
    let (output_tx, output_rx) = bounded::<Vec<Record>>(config.aggregation.output_queue_capacity);
    let mut aggregator = Aggregator::new(local, config.exclusions(), config.aggregation.max_flows);
    let seconds = config.aggregation.interval_seconds;
    let capture_stop = stop.clone();
    let capture_worker =
        thread::spawn(move || capture_loop(source, name, seconds, event_tx, capture_stop));
    let writer_stop = stop.clone();
    let writer = thread::spawn(move || -> Result<()> {
        for records in output_rx {
            if let Err(error) = output::append_enriched_window_with_reputation(
                &config.output.path,
                &ip_path,
                &records,
                enricher.as_ref(),
                reputation.as_ref(),
            ) {
                writer_stop.store(true, Ordering::Relaxed);
                return Err(error);
            }
        }
        Ok(())
    });
    tracing::info!(interval_seconds = seconds, "monitor started");
    let result = aggregate_loop(&event_rx, &output_tx, &mut aggregator);
    stop.store(true, Ordering::Relaxed);
    drop(event_rx); // Unblock a producer waiting to send a boundary after an output failure.
    drop(output_tx);
    let capture_result = capture_worker
        .join()
        .map_err(|_| anyhow!("capture worker panicked"))?;
    let writer_result = writer
        .join()
        .map_err(|_| anyhow!("output worker panicked"))?;
    writer_result.context("output failed; the last line/window may be incomplete")?;
    result?;
    capture_result?;
    tracing::info!("monitor stopped; final window flushed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Protocol;

    fn packet() -> PacketEvent {
        PacketEvent {
            protocol: Protocol::Udp,
            src_ip: "192.168.1.20".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 53,
            ip_length: 28,
        }
    }
    fn aggregator() -> Aggregator {
        Aggregator::new([packet().src_ip].into(), vec![], 10)
    }

    #[test]
    fn fifo_boundaries_and_shutdown_drain() {
        let (tx, rx) = bounded(10);
        let (out, records) = bounded(10);
        let end = DateTime::from_timestamp(1800000000, 0).unwrap();
        tx.send(Event::Packet(packet())).unwrap();
        tx.send(Event::Packet(packet())).unwrap();
        tx.send(Event::Boundary(end)).unwrap();
        tx.send(Event::Packet(packet())).unwrap();
        drop(tx);
        aggregate_loop(&rx, &out, &mut aggregator()).unwrap();
        let first = records.recv().unwrap();
        let final_window = records.recv().unwrap();
        assert_eq!(first[0].timestamp, end);
        assert_eq!(first[0].flow_byte_sum, 56);
        assert_eq!(first[0].flow_count, 1);
        assert_eq!(final_window[0].flow_byte_sum, 28);
        assert_eq!(final_window[0].flow_count, 1);
    }

    #[test]
    fn idle_boundary_emits_no_empty_records() {
        let (tx, rx) = bounded(1);
        let (out, records) = bounded(1);
        tx.send(Event::Boundary(Utc::now())).unwrap();
        drop(tx);
        aggregate_loop(&rx, &out, &mut aggregator()).unwrap();
        assert!(records.try_recv().is_err());
    }

    #[test]
    fn full_output_queue_is_explicit_failure() {
        let (tx, rx) = bounded(4);
        let (out, _records) = bounded(1);
        tx.send(Event::Packet(packet())).unwrap();
        tx.send(Event::Boundary(Utc::now())).unwrap();
        tx.send(Event::Packet(packet())).unwrap();
        tx.send(Event::Boundary(Utc::now())).unwrap();
        drop(tx);
        assert!(aggregate_loop(&rx, &out, &mut aggregator()).is_err());
    }

    #[test]
    fn writer_disconnect_fails_final_flush() {
        let (tx, rx) = bounded(1);
        let (out, records) = bounded(1);
        tx.send(Event::Packet(packet())).unwrap();
        drop(tx);
        drop(records);
        assert!(aggregate_loop(&rx, &out, &mut aggregator()).is_err());
    }
}
