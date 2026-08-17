use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementResult {
    Applied,
    Failed,
}

pub struct FirewallEnforcer;

impl FirewallEnforcer {
    pub fn new() -> Self {
        Self
    }

    pub fn block_ip(&self, source_ip: &str) -> EnforcementResult {
        let rule_name = format!("DDoS-Mitigation-{}", source_ip);

        let result = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_name),
                "dir=in",
                "action=block",
                &format!("remoteip={}", source_ip),
            ])
            .status();

        match result {
            Ok(status) if status.success() => EnforcementResult::Applied,
            _ => EnforcementResult::Failed,
        }
    }

    pub fn unblock_ip(&self, source_ip: &str) -> EnforcementResult {
        let rule_name = format!("DDoS-Mitigation-{}", source_ip);

        let result = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name),
            ])
            .status();

        match result {
            Ok(status) if status.success() => EnforcementResult::Applied,
            _ => EnforcementResult::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcement_result_variants_are_distinct() {
        assert_ne!(EnforcementResult::Applied, EnforcementResult::Failed);
    }

    #[test]
    fn enforcer_can_be_created() {
        let _enforcer = FirewallEnforcer::new();
    }
}
