use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metrics {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_alerts: u64,
    pub critical_alerts: u64,
    pub high_alerts: u64,
    pub medium_alerts: u64,
    pub low_alerts: u64,
    pub anomalies_detected: u64,
    pub mitigation_actions: u64,
    pub blocked_ips: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_packet(&mut self, bytes: u64) {
        self.total_packets += 1;
        self.total_bytes += bytes;
    }

    pub fn record_alert(&mut self) {
        self.total_alerts += 1;
    }

    pub fn record_critical_alert(&mut self) {
        self.critical_alerts += 1;
        self.total_alerts += 1;
    }

    pub fn record_high_alert(&mut self) {
        self.high_alerts += 1;
        self.total_alerts += 1;
    }

    pub fn record_medium_alert(&mut self) {
        self.medium_alerts += 1;
        self.total_alerts += 1;
    }

    pub fn record_low_alert(&mut self) {
        self.low_alerts += 1;
        self.total_alerts += 1;
    }

    pub fn record_anomaly(&mut self) {
        self.anomalies_detected += 1;
    }

    pub fn record_mitigation(&mut self) {
        self.mitigation_actions += 1;
    }

    pub fn set_blocked_ips(&mut self, count: usize) {
        self.blocked_ips = count as u64;
    }

    pub fn average_packet_size(&self) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }

        self.total_bytes as f64 / self.total_packets as f64
    }

    pub fn alert_rate(&self) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }

        self.total_alerts as f64 / self.total_packets as f64
    }

    pub fn anomaly_rate(&self) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }

        self.anomalies_detected as f64 / self.total_packets as f64
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let json = serde_json::to_string_pretty(self)?;

        fs::write(path, json)?;

        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let json = fs::read_to_string(path)?;

        let metrics = serde_json::from_str::<Self>(&json)?;

        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_file_path(name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();

        std::env::temp_dir().join(format!(
            "ddos_mitigation_metrics_{}_{}_{}.json",
            std::process::id(),
            name,
            timestamp
        ))
    }

    #[test]
    fn metrics_start_empty() {
        let metrics = Metrics::new();

        assert_eq!(metrics.total_packets, 0);
        assert_eq!(metrics.total_bytes, 0);
        assert_eq!(metrics.total_alerts, 0);
        assert_eq!(metrics.anomalies_detected, 0);
        assert_eq!(metrics.mitigation_actions, 0);
        assert_eq!(metrics.blocked_ips, 0);
    }

    #[test]
    fn records_packets_and_bytes() {
        let mut metrics = Metrics::new();

        metrics.record_packet(100);
        metrics.record_packet(200);

        assert_eq!(metrics.total_packets, 2);
        assert_eq!(metrics.total_bytes, 300);
    }

    #[test]
    fn calculates_average_packet_size() {
        let mut metrics = Metrics::new();

        metrics.record_packet(100);
        metrics.record_packet(200);

        assert_eq!(metrics.average_packet_size(), 150.0);
    }

    #[test]
    fn average_packet_size_is_zero_when_empty() {
        let metrics = Metrics::new();

        assert_eq!(metrics.average_packet_size(), 0.0);
    }

    #[test]
    fn records_alert_severities() {
        let mut metrics = Metrics::new();

        metrics.record_critical_alert();
        metrics.record_high_alert();
        metrics.record_high_alert();
        metrics.record_medium_alert();
        metrics.record_low_alert();

        assert_eq!(metrics.total_alerts, 5);
        assert_eq!(metrics.critical_alerts, 1);
        assert_eq!(metrics.high_alerts, 2);
        assert_eq!(metrics.medium_alerts, 1);
        assert_eq!(metrics.low_alerts, 1);
    }

    #[test]
    fn records_generic_alert() {
        let mut metrics = Metrics::new();

        metrics.record_alert();

        assert_eq!(metrics.total_alerts, 1);
    }

    #[test]
    fn records_anomalies() {
        let mut metrics = Metrics::new();

        metrics.record_anomaly();
        metrics.record_anomaly();

        assert_eq!(metrics.anomalies_detected, 2);
    }

    #[test]
    fn records_mitigations() {
        let mut metrics = Metrics::new();

        metrics.record_mitigation();
        metrics.record_mitigation();

        assert_eq!(metrics.mitigation_actions, 2);
    }

    #[test]
    fn tracks_blocked_ips() {
        let mut metrics = Metrics::new();

        metrics.set_blocked_ips(5);

        assert_eq!(metrics.blocked_ips, 5);
    }

    #[test]
    fn calculates_alert_rate() {
        let mut metrics = Metrics::new();

        metrics.record_packet(100);
        metrics.record_packet(100);
        metrics.record_alert();

        assert_eq!(metrics.alert_rate(), 0.5);
    }

    #[test]
    fn calculates_anomaly_rate() {
        let mut metrics = Metrics::new();

        metrics.record_packet(100);
        metrics.record_packet(100);
        metrics.record_anomaly();

        assert_eq!(metrics.anomaly_rate(), 0.5);
    }

    #[test]
    fn rates_are_zero_without_packets() {
        let metrics = Metrics::new();

        assert_eq!(metrics.alert_rate(), 0.0);
        assert_eq!(metrics.anomaly_rate(), 0.0);
    }

    #[test]
    fn reset_clears_metrics() {
        let mut metrics = Metrics::new();

        metrics.record_packet(500);
        metrics.record_anomaly();
        metrics.record_high_alert();
        metrics.record_mitigation();
        metrics.set_blocked_ips(2);

        metrics.reset();

        assert_eq!(metrics.total_packets, 0);
        assert_eq!(metrics.total_bytes, 0);
        assert_eq!(metrics.total_alerts, 0);
        assert_eq!(metrics.anomalies_detected, 0);
        assert_eq!(metrics.mitigation_actions, 0);
        assert_eq!(metrics.blocked_ips, 0);
    }

    #[test]
    fn saves_metrics_to_json_file() {
        let path = test_file_path("save");

        let mut metrics = Metrics::new();

        metrics.record_packet(500);
        metrics.record_packet(1000);
        metrics.record_high_alert();
        metrics.record_anomaly();
        metrics.record_mitigation();
        metrics.set_blocked_ips(2);

        metrics
            .save_to_file(&path)
            .expect("metrics should be saved");

        assert!(path.exists());

        let contents = fs::read_to_string(&path).expect("file should be readable");

        assert!(contents.contains("\"total_packets\": 2"));
        assert!(contents.contains("\"total_bytes\": 1500"));
        assert!(contents.contains("\"total_alerts\": 1"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_metrics_from_json_file() {
        let path = test_file_path("load");

        let mut original = Metrics::new();

        original.record_packet(500);
        original.record_packet(1000);
        original.record_high_alert();
        original.record_anomaly();
        original.record_mitigation();
        original.set_blocked_ips(2);

        original
            .save_to_file(&path)
            .expect("metrics should be saved");

        let loaded = Metrics::load_from_file(&path).expect("metrics should load");

        assert_eq!(loaded.total_packets, 2);
        assert_eq!(loaded.total_bytes, 1500);
        assert_eq!(loaded.total_alerts, 1);
        assert_eq!(loaded.high_alerts, 1);
        assert_eq!(loaded.anomalies_detected, 1);
        assert_eq!(loaded.mitigation_actions, 1);
        assert_eq!(loaded.blocked_ips, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn loading_missing_metrics_file_fails() {
        let path = test_file_path("missing");

        let result = Metrics::load_from_file(&path);

        assert!(result.is_err());
    }
}
