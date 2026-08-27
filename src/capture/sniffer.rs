use crate::alerts::{Alert, AlertManager, AlertSeverity};
use crate::analysis::AnalysisEngine;
use crate::capture::parser::parse_packet;
use crate::capture::stats::TrafficStats;
use crate::config::Config;
use crate::detection::detector::DetectionEngine;
use crate::metrics::Metrics;
use crate::mitigation::MitigationManager;
use crate::mitigation::enforcer::{EnforcementResult, FirewallEnforcer};
use pcap::{Capture, Device};

const ALERTS_FILE: &str = "data/alerts.json";
const METRICS_FILE: &str = "data/metrics.json";
const MAX_STORED_ALERTS: usize = 100;

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
                                let action = mitigation.block_ip(source_ip);

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
