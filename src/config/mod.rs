use std::env;

#[derive(Debug)]
pub struct Config {
    pub app_name: String,
    pub app_env: String,
    pub log_level: String,
    pub mitigation_score_threshold: f64,
    pub mitigation_block_duration_secs: u64,
    pub mitigation_enforcement_enabled: bool,
    pub mitigation_protected_ips: Vec<String>,
}

impl Config {
    pub fn from_env() -> Self {
        // Load .env from the project root.
        // Ignore the result because environment variables may already
        // be supplied by the operating system.
        let _ = dotenvy::from_filename(".env");

        Self {
            app_name: env::var("APP_NAME").unwrap_or_else(|_| "ddos-mitigation-tool".to_string()),

            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),

            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),

            mitigation_score_threshold: env::var("MITIGATION_SCORE_THRESHOLD")
                .ok()
                .and_then(|value| value.parse::<f64>().ok())
                .unwrap_or(0.75),

            mitigation_block_duration_secs: env::var("MITIGATION_BLOCK_DURATION_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60),

            mitigation_enforcement_enabled: env::var("MITIGATION_ENFORCEMENT_ENABLED")
                .ok()
                .and_then(|value| value.parse::<bool>().ok())
                .unwrap_or(false),

            mitigation_protected_ips: env::var("MITIGATION_PROTECTED_IPS")
                .unwrap_or_default()
                .split(',')
                .map(|ip| ip.trim().to_string())
                .filter(|ip| !ip.is_empty())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_loads_successfully() {
        let config = Config::from_env();

        assert!(!config.app_name.is_empty());
        assert!(!config.app_env.is_empty());
        assert!(!config.log_level.is_empty());

        assert!(config.mitigation_score_threshold > 0.0);
        assert!(config.mitigation_score_threshold <= 1.0);

        assert!(config.mitigation_block_duration_secs > 0);

        assert!(
            config
                .mitigation_protected_ips
                .contains(&"192.168.1.19".to_string())
        );
    }
}
