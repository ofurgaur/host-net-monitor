use anyhow::{Result, bail};
use host_net_monitor::{capture, config::Config, runtime};
use std::path::Path;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match execute() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "monitor failed");
            std::process::ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["list-interfaces"] => {
            for device in capture::devices()? {
                println!(
                    "{}\tup={}\t{}",
                    device.name,
                    device.flags.is_up(),
                    device
                        .addresses
                        .iter()
                        .map(|a| a.addr.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            Ok(())
        }
        ["check-config", path] => {
            let config = Config::load(Path::new(path))?;
            host_net_monitor::enrichment::Enricher::open(&config.enrichment)?;
            host_net_monitor::reputation::ReputationReader::open(&config.reputation)?;
            println!("Configuration is valid");
            Ok(())
        }
        ["run", "--config", path] => runtime::run(Config::load(Path::new(path))?),
        [] | ["--help"] | ["-h"] => {
            println!(
                "host-net-monitor\n\n  list-interfaces\n  check-config <config.yaml>\n  run --config <config.yaml>"
            );
            Ok(())
        }
        _ => bail!("invalid arguments; use --help"),
    }
}
