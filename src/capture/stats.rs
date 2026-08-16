use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct TrafficStats {
    pub packet_count: u64,
    pub byte_count: u64,

    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,

    source_ips: HashMap<String, u64>,
    destination_ports: HashMap<u16, u64>,

    window_start: Instant,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            packet_count: 0,
            byte_count: 0,
            tcp_packets: 0,
            udp_packets: 0,
            icmp_packets: 0,
            source_ips: HashMap::new(),
            destination_ports: HashMap::new(),
            window_start: Instant::now(),
        }
    }

    pub fn record_packet(
        &mut self,
        source_ip: Option<&str>,
        destination_port: Option<u16>,
        protocol: &str,
        packet_size: usize,
    ) {
        self.packet_count += 1;
        self.byte_count += packet_size as u64;

        match protocol.to_uppercase().as_str() {
            "TCP" => self.tcp_packets += 1,
            "UDP" => self.udp_packets += 1,
            "ICMP" => self.icmp_packets += 1,
            _ => {}
        }

        if let Some(ip) = source_ip {
            *self.source_ips.entry(ip.to_string()).or_insert(0) += 1;
        }

        if let Some(port) = destination_port {
            *self.destination_ports.entry(port).or_insert(0) += 1;
        }
    }

    pub fn should_report(&self) -> bool {
        self.window_start.elapsed() >= Duration::from_secs(1)
    }

    pub fn packets_per_second(&self) -> u64 {
        self.packet_count
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.byte_count
    }

    pub fn top_source_ips(&self, limit: usize) -> Vec<(&str, u64)> {
        let mut sources: Vec<(&str, u64)> = self
            .source_ips
            .iter()
            .map(|(ip, count)| (ip.as_str(), *count))
            .collect();

        sources.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        sources.truncate(limit);

        sources
    }

    pub fn top_destination_ports(&self, limit: usize) -> Vec<(u16, u64)> {
        let mut ports: Vec<(u16, u64)> = self
            .destination_ports
            .iter()
            .map(|(port, count)| (*port, *count))
            .collect();

        ports.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        ports.truncate(limit);

        ports
    }

    pub fn top_source_concentration(&self) -> f64 {
        if self.packet_count == 0 {
            return 0.0;
        }

        let top_count = self.source_ips.values().copied().max().unwrap_or(0);

        top_count as f64 / self.packet_count as f64
    }

    pub fn top_destination_port_concentration(&self) -> f64 {
        if self.packet_count == 0 {
            return 0.0;
        }

        let top_count = self.destination_ports.values().copied().max().unwrap_or(0);

        top_count as f64 / self.packet_count as f64
    }

    pub fn reset_window(&mut self) {
        self.packet_count = 0;
        self.byte_count = 0;

        self.tcp_packets = 0;
        self.udp_packets = 0;
        self.icmp_packets = 0;

        self.source_ips.clear();
        self.destination_ports.clear();

        self.window_start = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_packet_statistics() {
        let mut stats = TrafficStats::new();

        stats.record_packet(Some("192.168.1.10"), Some(443), "TCP", 100);

        assert_eq!(stats.packet_count, 1);
        assert_eq!(stats.byte_count, 100);
        assert_eq!(stats.tcp_packets, 1);
        assert_eq!(stats.udp_packets, 0);
        assert_eq!(stats.icmp_packets, 0);
    }

    #[test]
    fn tracks_top_source_ips() {
        let mut stats = TrafficStats::new();

        for _ in 0..5 {
            stats.record_packet(Some("192.168.1.10"), Some(443), "TCP", 100);
        }

        for _ in 0..2 {
            stats.record_packet(Some("192.168.1.20"), Some(443), "TCP", 100);
        }

        let top = stats.top_source_ips(2);

        assert_eq!(top[0], ("192.168.1.10", 5));
        assert_eq!(top[1], ("192.168.1.20", 2));
    }

    #[test]
    fn tracks_top_destination_ports() {
        let mut stats = TrafficStats::new();

        for _ in 0..5 {
            stats.record_packet(Some("192.168.1.10"), Some(443), "TCP", 100);
        }

        for _ in 0..2 {
            stats.record_packet(Some("192.168.1.10"), Some(80), "TCP", 100);
        }

        let top = stats.top_destination_ports(2);

        assert_eq!(top[0], (443, 5));
        assert_eq!(top[1], (80, 2));
    }

    #[test]
    fn calculates_top_source_concentration() {
        let mut stats = TrafficStats::new();

        for _ in 0..8 {
            stats.record_packet(Some("192.168.1.10"), Some(443), "TCP", 100);
        }

        for _ in 0..2 {
            stats.record_packet(Some("192.168.1.20"), Some(443), "TCP", 100);
        }

        assert_eq!(stats.top_source_concentration(), 0.8);
    }

    #[test]
    fn calculates_top_destination_port_concentration() {
        let mut stats = TrafficStats::new();

        for _ in 0..8 {
            stats.record_packet(Some("192.168.1.10"), Some(443), "TCP", 100);
        }

        for _ in 0..2 {
            stats.record_packet(Some("192.168.1.10"), Some(80), "TCP", 100);
        }

        let concentration = stats.top_destination_port_concentration();

        assert_eq!(concentration, 0.8);
    }

    #[test]
    fn reset_clears_statistics() {
        let mut stats = TrafficStats::new();

        stats.record_packet(Some("192.168.1.10"), Some(443), "TCP", 100);

        stats.reset_window();

        assert_eq!(stats.packet_count, 0);
        assert_eq!(stats.byte_count, 0);
        assert_eq!(stats.tcp_packets, 0);
        assert!(stats.top_source_ips(5).is_empty());
        assert!(stats.top_destination_ports(5).is_empty());
    }
}
