mod api;
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

    // Shared state for the live dashboard API.
    let state = api::new_shared_state();

    // Start the HTTP API alongside the packet-capture engine.
    let app = api::router(state.clone());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;

    info!("Live dashboard API listening on http://0.0.0.0:3000");

    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::error!(%error, "Live dashboard API stopped");
        }
    });

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

        let capture_device = device.clone();

        // pcap is blocking, so run the capture engine on a blocking Tokio thread.
        tokio::task::spawn_blocking(move || {
            sniffer::start_capture(capture_device, &config, state.clone())
        })
        .await??;
    } else {
        #[cfg(target_os = "linux")]
        eprintln!("Linux capture interface eth0 not found.");

        #[cfg(target_os = "windows")]
        eprintln!("Windows Wi-Fi/Intel interface not found.");
    }

    Ok(())
}
