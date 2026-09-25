use crate::packet::{self, PacketEvent, Skip};
use anyhow::{Context, Result, bail, ensure};
use std::{collections::HashSet, net::IpAddr};

#[cfg(target_os = "macos")]
const CAPTURE_PERMISSIONS: &str =
    "check the interface and /dev/bpf* access; use sudo or the LaunchDaemon";
#[cfg(target_os = "linux")]
const CAPTURE_PERMISSIONS: &str = "check the interface and CAP_NET_RAW permissions";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const CAPTURE_PERMISSIONS: &str = "check the interface, capture driver, and capture permissions";

pub enum Read {
    Packet(PacketEvent),
    Skipped(Skip),
    Idle,
}

/// Backends expose metadata only; packet buffers stay inside the backend.
pub trait CaptureSource {
    fn read(&mut self) -> Result<Read>;
    fn drops(&mut self) -> Result<(u32, u32)>;
}

pub struct PcapSource {
    capture: pcap::Capture<pcap::Active>,
    link: i32,
}

impl PcapSource {
    pub fn open(name: &str, promiscuous: bool) -> Result<Self> {
        let builder = pcap::Capture::from_device(name)?
            .promisc(promiscuous)
            .snaplen(512)
            .timeout(100)
            .buffer_size(4 * 1024 * 1024);
        // Deliver BPF packets immediately; the worker handles idle polling and timers.
        #[cfg(target_os = "macos")]
        let builder = builder.immediate_mode(true);
        let capture = builder
            .open()
            .with_context(|| format!("opening capture on {name}; {CAPTURE_PERMISSIONS}"))?
            .setnonblock()
            .context("enabling nonblocking capture")?;
        let link = capture.get_datalink().0;
        ensure!(
            packet::supported_link(link),
            "unsupported capture link type {link}"
        );
        Ok(Self { capture, link })
    }
}

impl CaptureSource for PcapSource {
    fn read(&mut self) -> Result<Read> {
        match self.capture.next_packet() {
            Ok(p) => Ok(match packet::parse(p.data, p.header.len, self.link) {
                Ok(event) => Read::Packet(event),
                Err(reason) => Read::Skipped(reason),
            }),
            Err(pcap::Error::TimeoutExpired) => Ok(Read::Idle),
            Err(e) => Err(e).context("reading packet capture"),
        }
    }
    fn drops(&mut self) -> Result<(u32, u32)> {
        let stats = self.capture.stats()?;
        Ok((stats.dropped, stats.if_dropped))
    }
}

pub fn devices() -> Result<Vec<pcap::Device>> {
    pcap::Device::list().context("enumerating interfaces")
}

pub fn local_addresses(selected: &str) -> Result<HashSet<IpAddr>> {
    let devices = devices()?;
    let Some(device) = devices.iter().find(|d| d.name == selected) else {
        bail!("capture interface {selected} disappeared or does not exist");
    };
    ensure!(device.flags.is_up(), "capture interface {selected} is down");
    let addresses: HashSet<_> = devices
        .iter()
        .filter(|d| d.flags.is_up())
        .flat_map(|d| d.addresses.iter().map(|a| a.addr))
        .collect();
    ensure!(
        !addresses.is_empty(),
        "no active local IP addresses discovered"
    );
    Ok(addresses)
}
