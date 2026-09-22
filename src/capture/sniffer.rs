use crate::api::{SharedState, TrafficSample};
use crate::alerts::{Alert, AlertManager, AlertSeverity};
use crate::analysis::AnalysisEngine;
use crate::capture::parser::parse_packet;
use crate::capture::stats::TrafficStats;
use crate::config::Config;
use crate::detection::detector::DetectionEngine;
use crate::metrics::Metrics;
use crate::mitigation::MitigationManager;
use crate::mitigation::enforcer::{EnforcementResult, FirewallEnforcer};
use crate::mitigation::xdp::XdpBlocker;
use pcap::{Capture, Device};
use std::collections::HashSet;

const ALERTS_FILE: &str = "data/alerts.json";
const METRICS_FILE: &str = "data/metrics.json";
const MITIGATION_HISTORY_FILE: &str = "data/mitigation_history.json";
const MAX_STORED_ALERTS: usize = 100;

pub fn start_capture(device: Device, config: &Config, state: SharedState) -> Result<(), pcap::Error> {
    println!("Opening interface: {}", device.name);
    let capture_interface_name = device.name.clone();

    let local_ipv4s: HashSet<String> = device
        .addresses
        .iter()
        .filter_map(|address| match address.addr {
            std::net::IpAddr::V4(ip) => Some(ip.to_string()),
            _ => None,
        })
        .collect();

    println!("Local capture IPv4 addresses: {:?}", local_ipv4s);

    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()?;

    {
        let mut live_state = state.write().expect("live state lock poisoned");
        live_state.engine_running = true;
        live_state.capture_interface = capture_interface_name.clone();
    }

    println!("Listening for packets...\n");

    let mut packet_count = 0u64;
    let mut stats = TrafficStats::new();
    let mut detector = DetectionEngine::new(10, 3.0, config.mitigation_score_threshold);

    let enforcer = FirewallEnforcer::new();

    let mut mitigation = MitigationManager::new(config.mitigation_block_duration_secs);

    match mitigation.load_history_from_file(MITIGATION_HISTORY_FILE) {
        Ok(()) => {
            println!(
                "Loaded {} persisted mitigation events.",
                mitigation.recent_history(100).len()
            );
        }
        Err(error) => {
            eprintln!(
                "Warning: could not load persisted mitigation history: {}",
                error
            );
        }
    }

    let mut xdp_blocker = match XdpBlocker::start(capture_interface_name.as_str()) {
        Ok(blocker) => {
            println!("XDP: program loaded, attached, and blocked_ips map ready");
            Some(blocker)
        }
        Err(error) => {
            eprintln!("XDP: automatic startup failed: {}", error);
            None
        }
    };

    {
        let mut live_state = state.write().expect("live state lock poisoned");
        live_state.protected_ips = config.mitigation_protected_ips.clone();
        live_state.xdp_enabled = xdp_blocker.is_some();
        live_state.firewall_enabled = config.mitigation_enforcement_enabled;
    }

    // Load previously persisted metrics.
    let mut metrics = match Metrics::load_from_file(METRICS_FILE) {
        Ok(metrics) => {
            println!(
                "Loaded persisted metrics: {} packets, {} alerts.",
                metrics.total_packets, metrics.total_alerts
            );

            metrics
        }

        Err(error) => {
            println!("No persisted metrics loaded: {}", error);

            Metrics::new()
        }
    };

    // Load previously persisted alerts.
    let mut alert_manager = match AlertManager::load_from_file(ALERTS_FILE, MAX_STORED_ALERTS) {
        Ok(manager) => {
            println!("Loaded {} persisted alerts.", manager.count());

            manager
        }

        Err(error) => {
            eprintln!("Warning: could not load persisted alerts: {}", error);

            AlertManager::new(MAX_STORED_ALERTS)
        }
    };

    // Restore persisted alert history into the live dashboard state.
    {
        let mut live_state = state.write().expect("live state lock poisoned");

        live_state.total_alerts = alert_manager.count() as u64;
        live_state.critical_alerts =
            alert_manager.count_by_severity(AlertSeverity::Critical) as u64;
        live_state.high_alerts =
            alert_manager.count_by_severity(AlertSeverity::High) as u64;
        live_state.medium_alerts =
            alert_manager.count_by_severity(AlertSeverity::Medium) as u64;
        live_state.low_alerts =
            alert_manager.count_by_severity(AlertSeverity::Low) as u64;

        live_state.recent_alerts = alert_manager
            .recent(10)
            .into_iter()
            .cloned()
            .collect();

        live_state.mitigation_history = mitigation.recent_history(10);
    }

    let analysis_engine = AnalysisEngine::new();

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

        // Record every captured packet.
        metrics.record_packet(info.packet_size as u64);

        let is_inbound = info
            .destination_ip
            .as_ref()
            .is_some_and(|destination| local_ipv4s.contains(destination));

        if is_inbound {
            stats.record_packet(
                info.source_ip.as_deref(),
                info.destination_port,
                &info.protocol,
                info.packet_size,
            );
        }

        if stats.should_report() {
            {
                let mut live_state = state.write().expect("live state lock poisoned");

                live_state.packets_per_second = stats.packets_per_second();
                live_state.bytes_per_second = stats.bytes_per_second();
                live_state.tcp_packets = stats.tcp_packets;
                live_state.udp_packets = stats.udp_packets;
                live_state.icmp_packets = stats.icmp_packets;

                live_state.top_source_ips = stats
                    .top_source_ips(5)
                    .into_iter()
                    .map(|(ip, packets)| crate::api::SourceStat { ip: ip.to_string(), packets })
                    .collect();

                live_state.top_destination_ports = stats
                    .top_destination_ports(5)
                    .into_iter()
                    .map(|(port, packets)| crate::api::PortStat { port, packets })
                    .collect();

                live_state.source_concentration =
                    stats.top_source_concentration();

                live_state.destination_port_concentration =
                    stats.top_destination_port_concentration();

                live_state.traffic_history.push(TrafficSample {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    packets_per_second: stats.packets_per_second(),
                    bytes_per_second: stats.bytes_per_second(),
                    tcp_packets: stats.tcp_packets,
                    udp_packets: stats.udp_packets,
                    icmp_packets: stats.icmp_packets,
                });

                if live_state.traffic_history.len() > 60 {
                    let excess = live_state.traffic_history.len() - 60;
                    live_state.traffic_history.drain(0..excess);
                }
            }

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
                    metrics.record_anomaly();

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

                    let source_ip = stats
                        .top_source_ips(1)
                        .first()
                        .map(|(ip, _)| (*ip).to_string());

                    let alert = Alert::from_anomaly(&result, source_ip.clone());

                    match alert.severity {
                        AlertSeverity::Critical => {
                            metrics.record_critical_alert();
                        }

                        AlertSeverity::High => {
                            metrics.record_high_alert();
                        }

                        AlertSeverity::Medium => {
                            metrics.record_medium_alert();
                        }

                        AlertSeverity::Low => {
                            metrics.record_low_alert();
                        }
                    }

                    println!(
                        "ALERT: {:?} | {:?} | score {:.2}%",
                        alert.severity,
                        alert.alert_type,
                        alert.anomaly_score * 100.0,
                    );

                    alert_manager.add(alert);

                    println!("Active alerts stored: {}", alert_manager.count());

                    match alert_manager.save_to_file(ALERTS_FILE) {
                        Ok(()) => {
                            println!("Alert history saved to {}", ALERTS_FILE);
                        }

                        Err(error) => {
                            eprintln!("Warning: failed to persist alerts: {}", error);
                        }
                    }

                    let report = analysis_engine.analyze(&alert_manager);

                    println!(
                        "\n--- Security Analysis ---\n\
                         Total alerts: {}\n\
                         Critical: {}\n\
                         High: {}\n\
                         Medium: {}\n\
                         Low: {}",
                        report.total_alerts,
                        report.critical_alerts,
                        report.high_alerts,
                        report.medium_alerts,
                        report.low_alerts,
                    );

                    if let Some(alert_type) = report.most_common_alert_type {
                        println!("Most common alert type: {:?}", alert_type);
                    }

                    if let Some(source_ip) = report.top_source_ip {
                        println!(
                            "Top alert source: {} ({} alerts)",
                            source_ip, report.top_source_count
                        );
                    }

                    if result.anomaly_score >= config.mitigation_score_threshold {
                        if let Some((source_ip, _)) = stats.top_source_ips(1).first().copied() {
                            if config
                                .mitigation_protected_ips
                                .iter()
                                .any(|ip| ip == source_ip)
                            {
                                println!("MITIGATION: skipped — protected local IP {}", source_ip);
                            } else {
                                let was_already_blocked = mitigation.is_blocked(source_ip);
                                let action = mitigation.block_ip(source_ip);

                                let mut xdp_applied = false;
                                let mut firewall_applied = false;

                                if let Some(blocker) = xdp_blocker.as_mut() {
                                    match source_ip.parse::<std::net::Ipv4Addr>() {
                                        Ok(ip) => match blocker.block(ip) {
                                            Ok(()) => {
                                                xdp_applied = true;
                                                println!(
                                                    "XDP: blocked IP {} added to eBPF map",
                                                    source_ip
                                                );
                                            }
                                            Err(error) => {
                                                eprintln!(
                                                    "XDP: failed to block {}: {}",
                                                    source_ip, error
                                                );
                                            }
                                        },
                                        Err(error) => {
                                            eprintln!(
                                                "XDP: invalid source IP {}: {}",
                                                source_ip, error
                                            );
                                        }
                                    }
                                }

                                println!(
                                    "MITIGATION: {:?} applied to source IP {}",
                                    action, source_ip
                                );

                                println!("Currently blocked IPs: {}", mitigation.blocked_count());

                                metrics.record_mitigation();

                                metrics.set_blocked_ips(mitigation.blocked_count());

                                if config.mitigation_enforcement_enabled {
                                    match enforcer.block_ip(source_ip) {
                                        EnforcementResult::Applied => {
                                            firewall_applied = true;
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

                                if !was_already_blocked {
                                    mitigation.record_event(
                                        source_ip,
                                        result.anomaly_score,
                                        xdp_applied,
                                        firewall_applied,
                                    );

                                    if let Err(error) =
                                        mitigation.save_history_to_file(MITIGATION_HISTORY_FILE)
                                    {
                                        eprintln!(
                                            "Warning: failed to persist mitigation history: {}",
                                            error
                                        );
                                    }

                                    let mut live_state =
                                        state.write().expect("live state lock poisoned");

                                    live_state.mitigation_history =
                                        mitigation.recent_history(10);
                                }
                            }
                        }
                    } else {
                        println!(
                            "MITIGATION: skipped | anomaly score {:.2}% \
                             below threshold {:.2}%",
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

            // Keep the latest blocked-IP count in metrics.
            metrics.set_blocked_ips(mitigation.blocked_count());

            // Persist metrics after every statistics window.
            match metrics.save_to_file(METRICS_FILE) {
                Ok(()) => {
                    println!("Metrics saved to {}", METRICS_FILE);
                }

                Err(error) => {
                    eprintln!("Warning: failed to persist metrics: {}", error);
                }
            }

            println!(
                "\n--- Runtime Metrics ---\n\
                 Total packets: {}\n\
                 Total bytes: {}\n\
                 Total alerts: {}\n\
                 Critical alerts: {}\n\
                 High alerts: {}\n\
                 Medium alerts: {}\n\
                 Low alerts: {}\n\
                 Anomalies detected: {}\n\
                 Mitigation actions: {}\n\
                 Blocked IPs: {}\n\
                 Average packet size: {:.2} bytes\n\
                 Alert rate: {:.4}\n\
                 Anomaly rate: {:.4}",
                metrics.total_packets,
                metrics.total_bytes,
                metrics.total_alerts,
                metrics.critical_alerts,
                metrics.high_alerts,
                metrics.medium_alerts,
                metrics.low_alerts,
                metrics.anomalies_detected,
                metrics.mitigation_actions,
                metrics.blocked_ips,
                metrics.average_packet_size(),
                metrics.alert_rate(),
                metrics.anomaly_rate(),
            );

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
