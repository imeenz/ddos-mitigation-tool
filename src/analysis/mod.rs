use std::collections::HashMap;

use crate::alerts::{AlertManager, AlertType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisReport {
    pub total_alerts: usize,
    pub critical_alerts: usize,
    pub high_alerts: usize,
    pub medium_alerts: usize,
    pub low_alerts: usize,
    pub most_common_alert_type: Option<AlertType>,
    pub top_source_ip: Option<String>,
    pub top_source_count: usize,
}

#[derive(Debug, Default)]
pub struct AnalysisEngine;

impl AnalysisEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, alerts: &AlertManager) -> AnalysisReport {
        let total_alerts = alerts.count();
        let critical_alerts = alerts.critical_count();
        let high_alerts = alerts.high_count();
        let medium_alerts = alerts.medium_count();
        let low_alerts = alerts.low_count();

        let recent_alerts = alerts.recent(total_alerts);

        let mut alert_type_counts: HashMap<AlertType, usize> = HashMap::new();

        let mut source_counts: HashMap<String, usize> = HashMap::new();

        for alert in recent_alerts {
            *alert_type_counts.entry(alert.alert_type).or_insert(0) += 1;

            if let Some(source_ip) = &alert.source_ip {
                *source_counts.entry(source_ip.clone()).or_insert(0) += 1;
            }
        }

        let most_common_alert_type = alert_type_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(alert_type, _)| alert_type);

        let (top_source_ip, top_source_count) = source_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ip, count)| (Some(ip), count))
            .unwrap_or((None, 0));

        AnalysisReport {
            total_alerts,
            critical_alerts,
            high_alerts,
            medium_alerts,
            low_alerts,
            most_common_alert_type,
            top_source_ip,
            top_source_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::alerts::{Alert, AlertSeverity};

    fn alert(severity: AlertSeverity, alert_type: AlertType, source_ip: Option<&str>) -> Alert {
        Alert::new(
            severity,
            alert_type,
            source_ip.map(|ip| ip.to_string()),
            500.0,
            0.85,
            "Test security alert",
        )
    }

    #[test]
    fn empty_alert_manager_produces_empty_report() {
        let manager = AlertManager::new(100);
        let engine = AnalysisEngine::new();

        let report = engine.analyze(&manager);

        assert_eq!(report.total_alerts, 0);
        assert_eq!(report.critical_alerts, 0);
        assert_eq!(report.high_alerts, 0);
        assert_eq!(report.medium_alerts, 0);
        assert_eq!(report.low_alerts, 0);
        assert_eq!(report.most_common_alert_type, None);
        assert_eq!(report.top_source_ip, None);
        assert_eq!(report.top_source_count, 0);
    }

    #[test]
    fn report_counts_alerts_by_severity() {
        let mut manager = AlertManager::new(100);

        manager.add(alert(
            AlertSeverity::Critical,
            AlertType::PotentialDDoS,
            Some("192.168.1.10"),
        ));

        manager.add(alert(
            AlertSeverity::Critical,
            AlertType::PotentialDDoS,
            Some("192.168.1.10"),
        ));

        manager.add(alert(
            AlertSeverity::High,
            AlertType::TrafficAnomaly,
            Some("192.168.1.20"),
        ));

        manager.add(alert(
            AlertSeverity::Medium,
            AlertType::TrafficAnomaly,
            Some("192.168.1.30"),
        ));

        manager.add(alert(
            AlertSeverity::Low,
            AlertType::TrafficAnomaly,
            Some("192.168.1.30"),
        ));

        let engine = AnalysisEngine::new();
        let report = engine.analyze(&manager);

        assert_eq!(report.total_alerts, 5);
        assert_eq!(report.critical_alerts, 2);
        assert_eq!(report.high_alerts, 1);
        assert_eq!(report.medium_alerts, 1);
        assert_eq!(report.low_alerts, 1);
    }

    #[test]
    fn identifies_most_common_alert_type() {
        let mut manager = AlertManager::new(100);

        manager.add(alert(
            AlertSeverity::High,
            AlertType::TrafficAnomaly,
            Some("192.168.1.10"),
        ));

        manager.add(alert(
            AlertSeverity::High,
            AlertType::TrafficAnomaly,
            Some("192.168.1.20"),
        ));

        manager.add(alert(
            AlertSeverity::Critical,
            AlertType::PotentialDDoS,
            Some("192.168.1.30"),
        ));

        let engine = AnalysisEngine::new();
        let report = engine.analyze(&manager);

        assert_eq!(
            report.most_common_alert_type,
            Some(AlertType::TrafficAnomaly)
        );
    }

    #[test]
    fn identifies_top_source_ip() {
        let mut manager = AlertManager::new(100);

        manager.add(alert(
            AlertSeverity::High,
            AlertType::TrafficAnomaly,
            Some("192.168.1.10"),
        ));

        manager.add(alert(
            AlertSeverity::Critical,
            AlertType::PotentialDDoS,
            Some("192.168.1.10"),
        ));

        manager.add(alert(
            AlertSeverity::Medium,
            AlertType::TrafficAnomaly,
            Some("192.168.1.20"),
        ));

        let engine = AnalysisEngine::new();
        let report = engine.analyze(&manager);

        assert_eq!(report.top_source_ip, Some("192.168.1.10".to_string()));

        assert_eq!(report.top_source_count, 2);
    }

    #[test]
    fn handles_alerts_without_source_ip() {
        let mut manager = AlertManager::new(100);

        manager.add(Alert::new(
            AlertSeverity::High,
            AlertType::TrafficAnomaly,
            None,
            500.0,
            0.85,
            "Unknown source",
        ));

        let engine = AnalysisEngine::new();
        let report = engine.analyze(&manager);

        assert_eq!(report.total_alerts, 1);
        assert_eq!(report.top_source_ip, None);
        assert_eq!(report.top_source_count, 0);
    }
}
