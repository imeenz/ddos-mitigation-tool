pub mod enforcer;

pub use enforcer::FirewallEnforcer;

use std::collections::HashMap;
use std::time::{Duration, Instant};

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

#[derive(Debug)]
pub struct MitigationManager {
    blocked_ips: HashMap<String, BlockEntry>,
    block_duration: Duration,
}

impl MitigationManager {
    pub fn new(block_duration_secs: u64) -> Self {
        Self {
            blocked_ips: HashMap::new(),
            block_duration: Duration::from_secs(block_duration_secs),
        }
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
