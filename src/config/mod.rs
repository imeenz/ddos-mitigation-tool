use std::env;

#[derive(Debug)]
pub struct Config {
    pub app_name: String,
    pub app_env: String,
    pub log_level: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        Self {
            app_name: env::var("APP_NAME").unwrap_or_else(|_| "ddos-mitigation-tool".to_string()),

            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),

            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
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
    }
}
