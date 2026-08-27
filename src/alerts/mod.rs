use std::collections::VecDeque;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::detection::detector::AnomalyResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertType {
    TrafficAnomaly,
    PotentialDDoS,
    MitigationTriggered,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub alert_type: AlertType,
    pub source_ip: Option<String>,
    pub packets_per_second: f64,
    pub anomaly_score: f64,
    pub message: String,
}

impl Alert {
    pub fn new(
        severity: AlertSeverity,
        alert_type: AlertType,
        source_ip: Option<String>,
        packets_per_second: f64,
        anomaly_score: f64,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            alert_type,
            source_ip,
            packets_per_second,
            anomaly_score,
            message: message.into(),
        }
    }

    pub fn from_anomaly(result: &AnomalyResult, source_ip: Option<String>) -> Self {
        let severity = AlertSeverity::from_anomaly_score(result.anomaly_score);

        let alert_type = if result.anomaly_score >= 0.90 {
            AlertType::PotentialDDoS
        } else {
            AlertType::TrafficAnomaly
        };

        let message = match alert_type {
            AlertType::PotentialDDoS => "Potential DDoS traffic pattern detected",
            AlertType::TrafficAnomaly => "Abnormal network traffic detected",
            AlertType::MitigationTriggered => "Network mitigation was triggered",
        };

        Self {
            severity,
            alert_type,
            source_ip,
            packets_per_second: result.current_value,
            anomaly_score: result.anomaly_score,
            message: message.to_string(),
        }
    }

    pub fn critical(
        alert_type: AlertType,
        source_ip: Option<String>,
        packets_per_second: f64,
        anomaly_score: f64,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            AlertSeverity::Critical,
            alert_type,
            source_ip,
            packets_per_second,
            anomaly_score,
            message,
        )
    }

    pub fn high(
        alert_type: AlertType,
        source_ip: Option<String>,
        packets_per_second: f64,
        anomaly_score: f64,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            AlertSeverity::High,
            alert_type,
            source_ip,
            packets_per_second,
            anomaly_score,
            message,
        )
    }

    pub fn medium(
        alert_type: AlertType,
        source_ip: Option<String>,
        packets_per_second: f64,
        anomaly_score: f64,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            AlertSeverity::Medium,
            alert_type,
            source_ip,
            packets_per_second,
            anomaly_score,
            message,
        )
    }

    pub fn low(
        alert_type: AlertType,
        source_ip: Option<String>,
        packets_per_second: f64,
        anomaly_score: f64,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            AlertSeverity::Low,
            alert_type,
            source_ip,
            packets_per_second,
            anomaly_score,
            message,
        )
    }
}

impl AlertSeverity {
    pub fn from_anomaly_score(score: f64) -> Self {
        if score >= 0.90 {
            AlertSeverity::Critical
        } else if score >= 0.80 {
            AlertSeverity::High
        } else if score >= 0.50 {
            AlertSeverity::Medium
        } else {
            AlertSeverity::Low
        }
    }
}

#[derive(Debug)]
pub struct AlertManager {
    alerts: VecDeque<Alert>,
    max_alerts: usize,
}

impl AlertManager {
    pub fn new(max_alerts: usize) -> Self {
        Self {
            alerts: VecDeque::with_capacity(max_alerts),
            max_alerts,
        }
    }

    pub fn add(&mut self, alert: Alert) {
        if self.max_alerts == 0 {
            return;
        }

        if self.alerts.len() >= self.max_alerts {
            self.alerts.pop_front();
        }

        self.alerts.push_back(alert);
    }

    pub fn count(&self) -> usize {
        self.alerts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.alerts.is_empty()
    }

    pub fn latest(&self) -> Option<&Alert> {
        self.alerts.back()
    }

    pub fn recent(&self, limit: usize) -> Vec<&Alert> {
        self.alerts.iter().rev().take(limit).collect()
    }

    pub fn count_by_severity(&self, severity: AlertSeverity) -> usize {
        self.alerts
            .iter()
            .filter(|alert| alert.severity == severity)
            .count()
    }

    pub fn critical_count(&self) -> usize {
        self.count_by_severity(AlertSeverity::Critical)
    }

    pub fn high_count(&self) -> usize {
        self.count_by_severity(AlertSeverity::High)
    }

    pub fn medium_count(&self) -> usize {
        self.count_by_severity(AlertSeverity::Medium)
    }

    pub fn low_count(&self) -> usize {
        self.count_by_severity(AlertSeverity::Low)
    }

    pub fn clear(&mut self) {
        self.alerts.clear();
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let alerts: Vec<&Alert> = self.alerts.iter().collect();

        let json = serde_json::to_string_pretty(&alerts)?;

        fs::write(path, json)?;

        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
        max_alerts: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.as_ref().exists() {
            return Ok(Self::new(max_alerts));
        }

        let contents = fs::read_to_string(path)?;

        if contents.trim().is_empty() {
            return Ok(Self::new(max_alerts));
        }

        let stored_alerts: Vec<Alert> = serde_json::from_str(&contents)?;

        let mut manager = Self::new(max_alerts);

        for alert in stored_alerts {
            manager.add(alert);
        }

        Ok(manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_alert(severity: AlertSeverity) -> Alert {
        Alert::new(
            severity,
            AlertType::TrafficAnomaly,
            Some("192.168.1.100".to_string()),
            500.0,
            0.85,
            "Test alert",
        )
    }

    fn test_anomaly(score: f64) -> AnomalyResult {
        AnomalyResult {
            current_value: 500.0,
            z_score: 5.0,
            source_concentration: 0.75,
            destination_port_concentration: 0.70,
            anomaly_score: score,
            anomalous: score >= 0.80,
        }
    }

    #[test]
    fn creates_alert_successfully() {
        let alert = Alert::new(
            AlertSeverity::High,
            AlertType::TrafficAnomaly,
            Some("192.168.1.100".to_string()),
            500.0,
            0.85,
            "Abnormal traffic detected",
        );

        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.alert_type, AlertType::TrafficAnomaly);
        assert_eq!(alert.source_ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(alert.packets_per_second, 500.0);
        assert_eq!(alert.anomaly_score, 0.85);
        assert_eq!(alert.message, "Abnormal traffic detected");
    }

    #[test]
    fn critical_alert_has_critical_severity() {
        let alert = Alert::critical(
            AlertType::PotentialDDoS,
            Some("10.0.0.50".to_string()),
            1000.0,
            0.95,
            "Potential DDoS attack detected",
        );

        assert_eq!(alert.severity, AlertSeverity::Critical);
    }

    #[test]
    fn high_alert_has_high_severity() {
        let alert = Alert::high(
            AlertType::TrafficAnomaly,
            None,
            400.0,
            0.75,
            "High traffic anomaly",
        );

        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn alert_can_have_no_source_ip() {
        let alert = Alert::low(
            AlertType::TrafficAnomaly,
            None,
            100.0,
            0.20,
            "Low severity anomaly",
        );

        assert_eq!(alert.source_ip, None);
    }

    #[test]
    fn severity_is_critical_for_very_high_score() {
        assert_eq!(
            AlertSeverity::from_anomaly_score(0.95),
            AlertSeverity::Critical
        );
    }

    #[test]
    fn severity_is_high_for_anomalous_score() {
        assert_eq!(AlertSeverity::from_anomaly_score(0.85), AlertSeverity::High);
    }

    #[test]
    fn severity_is_medium_for_moderate_score() {
        assert_eq!(
            AlertSeverity::from_anomaly_score(0.60),
            AlertSeverity::Medium
        );
    }

    #[test]
    fn severity_is_low_for_low_score() {
        assert_eq!(AlertSeverity::from_anomaly_score(0.30), AlertSeverity::Low);
    }

    #[test]
    fn alert_can_be_created_from_anomaly_result() {
        let result = test_anomaly(0.85);

        let alert = Alert::from_anomaly(&result, Some("192.168.1.100".to_string()));

        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.alert_type, AlertType::TrafficAnomaly);
        assert_eq!(alert.source_ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(alert.packets_per_second, 500.0);
        assert_eq!(alert.anomaly_score, 0.85);
    }

    #[test]
    fn very_high_anomaly_is_potential_ddos() {
        let result = test_anomaly(0.95);

        let alert = Alert::from_anomaly(&result, None);

        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.alert_type, AlertType::PotentialDDoS);
    }

    #[test]
    fn manager_starts_empty() {
        let manager = AlertManager::new(100);

        assert_eq!(manager.count(), 0);
        assert!(manager.is_empty());
        assert!(manager.latest().is_none());
    }

    #[test]
    fn manager_stores_alert() {
        let mut manager = AlertManager::new(100);

        manager.add(test_alert(AlertSeverity::High));

        assert_eq!(manager.count(), 1);
        assert!(!manager.is_empty());
        assert!(manager.latest().is_some());
    }

    #[test]
    fn latest_returns_most_recent_alert() {
        let mut manager = AlertManager::new(100);

        manager.add(test_alert(AlertSeverity::Low));
        manager.add(test_alert(AlertSeverity::Critical));

        assert_eq!(manager.latest().unwrap().severity, AlertSeverity::Critical);
    }

    #[test]
    fn manager_limits_alert_storage() {
        let mut manager = AlertManager::new(2);

        manager.add(test_alert(AlertSeverity::Low));
        manager.add(test_alert(AlertSeverity::Medium));
        manager.add(test_alert(AlertSeverity::Critical));

        assert_eq!(manager.count(), 2);
        assert_eq!(manager.recent(2)[0].severity, AlertSeverity::Critical);
        assert_eq!(manager.recent(2)[1].severity, AlertSeverity::Medium);
    }

    #[test]
    fn recent_returns_newest_first() {
        let mut manager = AlertManager::new(10);

        manager.add(test_alert(AlertSeverity::Low));
        manager.add(test_alert(AlertSeverity::High));
        manager.add(test_alert(AlertSeverity::Critical));

        let recent = manager.recent(2);

        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].severity, AlertSeverity::Critical);
        assert_eq!(recent[1].severity, AlertSeverity::High);
    }

    #[test]
    fn recent_limit_can_be_smaller_than_total() {
        let mut manager = AlertManager::new(10);

        manager.add(test_alert(AlertSeverity::Low));
        manager.add(test_alert(AlertSeverity::Medium));
        manager.add(test_alert(AlertSeverity::High));

        assert_eq!(manager.recent(1).len(), 1);
        assert_eq!(manager.recent(5).len(), 3);
    }

    #[test]
    fn counts_alerts_by_severity() {
        let mut manager = AlertManager::new(10);

        manager.add(test_alert(AlertSeverity::Critical));
        manager.add(test_alert(AlertSeverity::Critical));
        manager.add(test_alert(AlertSeverity::High));
        manager.add(test_alert(AlertSeverity::Medium));
        manager.add(test_alert(AlertSeverity::Low));

        assert_eq!(manager.critical_count(), 2);
        assert_eq!(manager.high_count(), 1);
        assert_eq!(manager.medium_count(), 1);
        assert_eq!(manager.low_count(), 1);
    }

    #[test]
    fn clear_removes_all_alerts() {
        let mut manager = AlertManager::new(10);

        manager.add(test_alert(AlertSeverity::High));
        manager.add(test_alert(AlertSeverity::Critical));

        manager.clear();

        assert_eq!(manager.count(), 0);
        assert!(manager.is_empty());
        assert!(manager.latest().is_none());
    }

    #[test]
    fn zero_capacity_manager_stays_empty() {
        let mut manager = AlertManager::new(0);

        manager.add(test_alert(AlertSeverity::Critical));

        assert_eq!(manager.count(), 0);
        assert!(manager.is_empty());
    }

    #[test]
    fn alerts_can_be_serialized_to_json() {
        let alert = test_alert(AlertSeverity::High);

        let json = serde_json::to_string(&alert).unwrap();

        assert!(json.contains("TrafficAnomaly"));
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("0.85"));
    }

    #[test]
    fn alerts_can_be_deserialized_from_json() {
        let alert = test_alert(AlertSeverity::Critical);

        let json = serde_json::to_string(&alert).unwrap();

        let restored: Alert = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, alert);
    }
}
