pub mod enforcer;

pub use enforcer::FirewallEnforcer;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitigationAction {
    Block,
    Unblock,
}

#[derive(Debug, Clone)]
pub struct BlockEntry {
    pub source_ip: String,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationEvent {
    pub timestamp: u64,
    pub source_ip: String,
    pub anomaly_score: f64,
    pub xdp_applied: bool,
    pub firewall_applied: bool,
}

#[derive(Debug)]
pub struct MitigationManager {
    blocked_ips: HashMap<String, BlockEntry>,
    block_duration: Duration,
    history: Vec<MitigationEvent>,
    max_history: usize,
}

impl MitigationManager {
    pub fn new(block_duration_secs: u64) -> Self {
        Self {
            blocked_ips: HashMap::new(),
            block_duration: Duration::from_secs(block_duration_secs),
            history: Vec::new(),
            max_history: 100,
        }
    }

    pub fn record_event(
        &mut self,
        source_ip: &str,
        anomaly_score: f64,
        xdp_applied: bool,
        firewall_applied: bool,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.history.len() >= self.max_history {
            self.history.remove(0);
        }

        self.history.push(MitigationEvent {
            timestamp,
            source_ip: source_ip.to_string(),
            anomaly_score,
            xdp_applied,
            firewall_applied,
        });
    }

    pub fn recent_history(&self, limit: usize) -> Vec<MitigationEvent> {
        self.history.iter().rev().take(limit).cloned().collect()
    }

    pub fn load_history_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !path.as_ref().exists() {
            return Ok(());
        }

        let contents = fs::read_to_string(path)?;

        if contents.trim().is_empty() {
            return Ok(());
        }

        let mut history: Vec<MitigationEvent> = serde_json::from_str(&contents)?;

        if history.len() > self.max_history {
            history = history.split_off(history.len() - self.max_history);
        }

        self.history = history;

        Ok(())
    }

    pub fn save_history_to_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&self.history)?;
        fs::write(path, json)?;

        Ok(())
    }
    pub fn should_mitigate(&self, anomaly_score: f64, threshold: f64) -> bool {
        anomaly_score >= threshold
    }

    pub fn block_ip(&mut self, source_ip: &str) -> MitigationAction {
        self.remove_expired();

        if self.blocked_ips.contains_key(source_ip) {
            return MitigationAction::Block;
        }

        let expires_at = Instant::now() + self.block_duration;

        self.blocked_ips.insert(
            source_ip.to_string(),
            BlockEntry {
                source_ip: source_ip.to_string(),
                expires_at,
            },
        );

        MitigationAction::Block
    }

    pub fn is_blocked(&mut self, source_ip: &str) -> bool {
        self.remove_expired();

        self.blocked_ips.contains_key(source_ip)
    }

    pub fn unblock_ip(&mut self, source_ip: &str) -> Option<MitigationAction> {
        if self.blocked_ips.remove(source_ip).is_some() {
            Some(MitigationAction::Unblock)
        } else {
            None
        }
    }

    pub fn blocked_count(&mut self) -> usize {
        self.remove_expired();

        self.blocked_ips.len()
    }

    pub fn blocked_ips_snapshot(&mut self) -> Vec<(String, u64)> {
        self.remove_expired();

        let now = Instant::now();

        self.blocked_ips
            .values()
            .map(|entry| {
                let remaining_secs = entry
                    .expires_at
                    .checked_duration_since(now)
                    .unwrap_or_default()
                    .as_secs();

                (entry.source_ip.clone(), remaining_secs)
            })
            .collect()
    }

    pub fn remove_expired(&mut self) {
        let now = Instant::now();

        self.blocked_ips.retain(|_, entry| entry.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_starts_empty() {
        let mut manager = MitigationManager::new(60);

        assert_eq!(manager.blocked_count(), 0);
    }

    #[test]
    fn blocks_ip() {
        let mut manager = MitigationManager::new(60);

        let action = manager.block_ip("192.168.1.100");

        assert_eq!(action, MitigationAction::Block);
        assert!(manager.is_blocked("192.168.1.100"));
    }
    #[test]
    fn blocking_already_blocked_ip_does_not_duplicate_entry() {
        let mut manager = MitigationManager::new(60);
        manager.block_ip("192.168.1.100");
        manager.block_ip("192.168.1.100");

        assert_eq!(manager.blocked_count(), 1);
        assert!(manager.is_blocked("192.168.1.100"));
    }

    #[test]
    fn different_ip_is_not_blocked() {
        let mut manager = MitigationManager::new(60);

        manager.block_ip("192.168.1.100");

        assert!(!manager.is_blocked("192.168.1.200"));
    }

    #[test]
    fn unblock_removes_ip() {
        let mut manager = MitigationManager::new(60);

        manager.block_ip("192.168.1.100");

        let action = manager.unblock_ip("192.168.1.100");

        assert_eq!(action, Some(MitigationAction::Unblock));
        assert!(!manager.is_blocked("192.168.1.100"));
    }

    #[test]
    fn unblocking_unknown_ip_returns_none() {
        let mut manager = MitigationManager::new(60);

        assert_eq!(manager.unblock_ip("192.168.1.100"), None);
    }

    #[test]
    fn multiple_ips_can_be_blocked() {
        let mut manager = MitigationManager::new(60);

        manager.block_ip("192.168.1.100");
        manager.block_ip("192.168.1.101");
        manager.block_ip("192.168.1.102");

        assert_eq!(manager.blocked_count(), 3);
    }
    #[test]
    fn score_below_threshold_does_not_trigger_mitigation() {
        let manager = MitigationManager::new(60);
        assert!(!manager.should_mitigate(0.50, 0.75));
    }
    #[test]
    fn score_at_threshold_triggers_mitigation() {
        let manager = MitigationManager::new(60);

        assert!(manager.should_mitigate(0.75, 0.75));
    }
    #[test]
    fn score_above_threshold_triggers_mitigation() {
        let manager = MitigationManager::new(60);

        assert!(manager.should_mitigate(0.90, 0.75));
    }
}

pub mod xdp;
