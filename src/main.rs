mod alerts;
mod analysis;
mod capture;
mod config;
mod detection;
mod metrics;
mod mitigation;

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

    Ok(())
}
