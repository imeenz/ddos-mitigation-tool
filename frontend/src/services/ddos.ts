import axios from "axios"

export interface TrafficSample {
  timestamp: number
  packets_per_second: number
  bytes_per_second: number
  tcp_packets: number
  udp_packets: number
  icmp_packets: number
}

export interface DdosState {
  engine_running: boolean
  capture_interface: string
  xdp_enabled: boolean
  firewall_enabled: boolean
  protected_ips: string[]

  packets_per_second: number
  bytes_per_second: number
  traffic_history: TrafficSample[]

  tcp_packets: number
  udp_packets: number
  icmp_packets: number

  top_source_ips: {
    ip: string
    packets: number
  }[]

  top_destination_ports: {
    port: number
    packets: number
  }[]

  source_concentration: number
  destination_port_concentration: number

  anomaly_score: number
  z_score: number

  active_blocked_ips: number

  total_alerts: number
  critical_alerts: number
  high_alerts: number
  medium_alerts: number
  low_alerts: number

  xdp_blocks: number
  firewall_blocks: number

  blocked_ips: {
    ip: string
    remaining_seconds: number
  }[]

  mitigation_history: {
    timestamp: number
    source_ip: string
    anomaly_score: number
    xdp_applied: boolean
    firewall_applied: boolean
  }[]

  recent_alerts: {
    severity: "Low" | "Medium" | "High" | "Critical"
    alert_type:
      | "TrafficAnomaly"
      | "PotentialDDoS"
      | "MitigationTriggered"
    source_ip: string | null
    packets_per_second: number
    anomaly_score: number
    message: string
  }[]
}

const ddosApi = axios.create({
  baseURL: "/api",
})

export async function getDdosState(): Promise<DdosState> {
  const response = await ddosApi.get<DdosState>("/state")

  return {
    ...response.data,
    blocked_ips: response.data.blocked_ips ?? [],
    mitigation_history: response.data.mitigation_history ?? [],
    recent_alerts: response.data.recent_alerts ?? [],
    top_source_ips: response.data.top_source_ips ?? [],
    top_destination_ports: response.data.top_destination_ports ?? [],
  }
}
