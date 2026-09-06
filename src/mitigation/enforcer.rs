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
        #[cfg(target_os = "windows")]
        {
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

        #[cfg(target_os = "linux")]
        {
            if !Self::ensure_nftables_structure() {
                return EnforcementResult::Failed;
            }

            let result = Command::new("nft")
                .args([
                    "add",
                    "element",
                    "inet",
                    "ddos_mitigation",
                    "blocked_ips",
                    "{",
                    source_ip,
                    "timeout",
                    "60s",
                    "}",
                ])
                .status();

            match result {
                Ok(status) if status.success() => EnforcementResult::Applied,
                _ => EnforcementResult::Failed,
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            EnforcementResult::Failed
        }
    }

    pub fn unblock_ip(&self, source_ip: &str) -> EnforcementResult {
        #[cfg(target_os = "windows")]
        {
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

        #[cfg(target_os = "linux")]
        {
            let result = Command::new("nft")
                .args([
                    "delete",
                    "element",
                    "inet",
                    "ddos_mitigation",
                    "blocked_ips",
                    "{",
                    source_ip,
                    "}",
                ])
                .status();

            match result {
                Ok(status) if status.success() => EnforcementResult::Applied,
                _ => EnforcementResult::Failed,
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            EnforcementResult::Failed
        }
    }

    #[cfg(target_os = "linux")]
    fn ensure_nftables_structure() -> bool {
        let table_exists = Command::new("nft")
            .args(["list", "table", "inet", "ddos_mitigation"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if !table_exists {
            let table_created = Command::new("nft")
                .args(["add", "table", "inet", "ddos_mitigation"])
                .status()
                .map(|status| status.success())
                .unwrap_or(false);

            if !table_created {
                return false;
            }
        }

        let set_exists = Command::new("nft")
            .args(["list", "set", "inet", "ddos_mitigation", "blocked_ips"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if !set_exists {
            let set_created = Command::new("nft")
                .args([
                    "add",
                    "set",
                    "inet",
                    "ddos_mitigation",
                    "blocked_ips",
                    "{",
                    "type",
                    "ipv4_addr",
                    ";",
                    "flags",
                    "timeout",
                    ";",
                    "}",
                ])
                .status()
                .map(|status| status.success())
                .unwrap_or(false);

            if !set_created {
                return false;
            }
        }

        true
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_enforcer_can_block_and_unblock_ip() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping Linux firewall integration test: root privileges required");
            return;
        }

        let enforcer = FirewallEnforcer::new();
        let test_ip = "192.0.2.1";

        assert_eq!(enforcer.block_ip(test_ip), EnforcementResult::Applied);

        assert_eq!(enforcer.unblock_ip(test_ip), EnforcementResult::Applied);
    }
}
