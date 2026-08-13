use crate::capture::parser::parse_packet;
use crate::capture::stats::TrafficStats;
use pcap::{Capture, Device};

pub fn start_capture(device: Device) -> Result<(), pcap::Error> {
    println!("Opening interface: {}", device.name);

    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .open()?;

    println!("Listening for packets...\n");

    let mut packet_count = 0u64;
    let mut stats = TrafficStats::new();

    while let Ok(packet) = capture.next_packet() {
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
                println!("  {} → {} packets", ip, count);
            }
            println!("Top destination ports:");
            for (port, count) in stats.top_destination_ports(5) {
                println!("  port {} → {} packets", port, count);
            }

            stats.reset_window();
        }

        if packet_count.is_multiple_of(100) {
            println!(
                "Processed {} packets | Latest: {}:{} → {}:{} | {}",
                packet_count,
                info.source_ip.as_deref().unwrap_or("-"),
                info.source_port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                info.destination_ip.as_deref().unwrap_or("-"),
                info.destination_port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                info.protocol
            );
        }
    }

    Ok(())
}
