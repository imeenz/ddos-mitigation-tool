use crate::capture::parser::parse_packet;
use crate::capture::stats::TrafficStats;
use crate::config::Config;
use crate::detection::detector::DetectionEngine;
use crate::mitigation::MitigationManager;
use crate::mitigation::enforcer::{EnforcementResult, FirewallEnforcer};
use pcap::{Capture, Device};

pub fn start_capture(device: Device, config: &Config) -> Result<(), pcap::Error> {
    println!("Opening interface: {}", device.name);

    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()?;

    println!("Listening for packets...\n");

    let mut packet_count = 0u64;
    let mut stats = TrafficStats::new();
    let mut detector = DetectionEngine::new(10, 3.0);
    let enforcer = FirewallEnforcer::new();
    let mut mitigation = MitigationManager::new(config.mitigation_block_duration_secs);

    loop {
        let packet = match capture.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(error) => {
                eprintln!("Capture error: {}", error);
                break;
            }
        };

        packet_count += 1;

        let info = parse_packet(packet.data);

        stats.record_packet(
            info.source_ip.as_deref(),
            info.destination_port,
            &info.protocol,
            info.packet_size,
        );

        if stats.should_report() {
            println!(
                "\n--- Traffic Statistics ---\n\
                 Packets/sec: {}\n\
                 Bytes/sec: {}\n\
                 TCP: {}\n\
                 UDP: {}\n\
                 ICMP: {}\n",
                stats.packets_per_second(),
                stats.bytes_per_second(),
                stats.tcp_packets,
                stats.udp_packets,
                stats.icmp_packets,
            );

            println!("Top source IPs:");

            for (ip, count) in stats.top_source_ips(5) {
                println!("  {} -> {} packets", ip, count);
            }

            println!("Top destination ports:");

            for (port, count) in stats.top_destination_ports(5) {
                println!("  port {} -> {} packets", port, count);
            }

            let source_concentration = stats.top_source_concentration();
            let destination_port_concentration = stats.top_destination_port_concentration();

            if let Some(result) = detector.process(
                stats.packets_per_second(),
                source_concentration,
                destination_port_concentration,
            ) {
                if result.anomalous {
                    println!(
                        "\n!!! ANOMALY DETECTED !!!\n\
                         Packets/sec: {:.2}\n\
                         Z-score: {:.2}\n\
                         Source concentration: {:.2}%\n\
                         Destination port concentration: {:.2}%\n\
                         Combined anomaly score: {:.2}%\n",
                        result.current_value,
                        result.z_score,
                        result.source_concentration * 100.0,
                        result.destination_port_concentration * 100.0,
                        result.anomaly_score * 100.0,
                    );

                    if result.anomaly_score >= config.mitigation_score_threshold {
                        if let Some((source_ip, _)) = stats.top_source_ips(1).first().copied() {
                            if config
                                .mitigation_protected_ips
                                .iter()
                                .any(|ip| ip == source_ip)
                            {
                                println!("MITIGATION: skipped — protected local IP {}", source_ip);
                            } else {
                                let action = mitigation.block_ip(source_ip);

                                println!(
                                    "MITIGATION: {:?} applied to source IP {}",
                                    action, source_ip
                                );

                                println!("Currently blocked IPs: {}", mitigation.blocked_count());

                                if config.mitigation_enforcement_enabled {
                                    match enforcer.block_ip(source_ip) {
                                        EnforcementResult::Applied => {
                                            println!(
                                                "ENFORCEMENT: firewall block applied to {}",
                                                source_ip
                                            );
                                        }

                                        EnforcementResult::Failed => {
                                            eprintln!(
                                                "ENFORCEMENT: failed to block {} in Windows Firewall",
                                                source_ip
                                            );
                                        }
                                    }
                                } else {
                                    println!("ENFORCEMENT: disabled — no firewall rule applied");
                                }
                            }
                        }
                    } else {
                        println!(
                            "MITIGATION: skipped | anomaly score {:.2}% below threshold {:.2}%",
                            result.anomaly_score * 100.0,
                            config.mitigation_score_threshold * 100.0
                        );
                    }
                } else {
                    println!(
                        "Traffic normal | Z-score: {:.2} | \
                         Source concentration: {:.2}% | \
                         Destination port concentration: {:.2}% | \
                         Anomaly score: {:.2}%",
                        result.z_score,
                        result.source_concentration * 100.0,
                        result.destination_port_concentration * 100.0,
                        result.anomaly_score * 100.0,
                    );
                }
            } else {
                println!("Learning baseline: {}/10 samples", detector.sample_count());
            }

            stats.reset_window();
        }

        if packet_count.is_multiple_of(100) {
            println!(
                "Processed {} packets | Latest: {}:{} -> {}:{} | {}",
                packet_count,
                info.source_ip.as_deref().unwrap_or("-"),
                info.source_port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                info.destination_ip.as_deref().unwrap_or("-"),
                info.destination_port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                info.protocol,
            );
        }
    }

    Ok(())
}
