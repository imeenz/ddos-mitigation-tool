use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

#[derive(Debug)]
pub struct PacketInfo {
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub packet_size: usize,
}

pub fn parse_packet(data: &[u8]) -> PacketInfo {
    let packet_size = data.len();

    match SlicedPacket::from_ethernet(data) {
        Ok(packet) => {
            let (source_ip, destination_ip) = match packet.net {
                Some(InternetSlice::Ipv4(header)) => (
                    Some(header.header().source_addr().to_string()),
                    Some(header.header().destination_addr().to_string()),
                ),

                Some(InternetSlice::Ipv6(header)) => (
                    Some(header.header().source_addr().to_string()),
                    Some(header.header().destination_addr().to_string()),
                ),

                _ => (None, None),
            };

            let (protocol, source_port, destination_port) = match packet.transport {
                Some(TransportSlice::Tcp(tcp)) => (
                    "TCP".to_string(),
                    Some(tcp.source_port()),
                    Some(tcp.destination_port()),
                ),

                Some(TransportSlice::Udp(udp)) => (
                    "UDP".to_string(),
                    Some(udp.source_port()),
                    Some(udp.destination_port()),
                ),

                Some(TransportSlice::Icmpv4(_)) => ("ICMPv4".to_string(), None, None),

                Some(TransportSlice::Icmpv6(_)) => ("ICMPv6".to_string(), None, None),

                Some(TransportSlice::Igmp(_)) => ("IGMP".to_string(), None, None),

                None => ("Unknown".to_string(), None, None),
            };

            PacketInfo {
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_size,
            }
        }

        Err(_) => PacketInfo {
            source_ip: None,
            destination_ip: None,
            protocol: "Unknown".to_string(),
            source_port: None,
            destination_port: None,
            packet_size,
        },
    }
}
