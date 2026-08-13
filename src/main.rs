mod alerts;
mod analysis;
mod capture;
mod config;
mod detection;
mod metrics;
mod mitigation;

use capture::device;
use config::Config;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("DDoS Mitigation Tool starting");
    info!("Network security engine initialized");

    let config = Config::from_env();

    info!(
        app = %config.app_name,
        environment = %config.app_env,
        log_level = %config.log_level,
        "Configuration loaded"
    );
    let devices = device::list_interfaces()?;
    if let Some(device) = devices.into_iter().find(|device| {
        device
            .desc
            .as_deref()
            .map(|desc| desc.contains("Intel"))
            .unwrap_or(false)
    }) {
        capture::sniffer::start_capture(device)?;
    } else {
        eprintln!("Wi-Fi interface not found.");
    }
    Ok(())
}
