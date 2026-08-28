mod alerts;
mod analysis;
mod capture;
mod config;
mod detection;
mod metrics;
mod mitigation;

use anyhow::Result;
use tracing::info;

use crate::capture::device;
use crate::capture::sniffer;
use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
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

    #[cfg(target_os = "linux")]
    let capture_device = devices.iter().find(|device| device.name == "eth0");

    #[cfg(target_os = "windows")]
    let capture_device = devices.iter().find(|device| {
        device
            .desc
            .as_deref()
            .map(|desc| desc.contains("Intel"))
            .unwrap_or(false)
    });

    if let Some(device) = capture_device {
        info!(interface = %device.name, "Selected capture interface");

        sniffer::start_capture(device.clone(), &config)?;
    } else {
        #[cfg(target_os = "linux")]
        eprintln!("Linux capture interface eth0 not found.");

        #[cfg(target_os = "windows")]
        eprintln!("Windows Wi-Fi/Intel interface not found.");
    }

    Ok(())
}
