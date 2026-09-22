use axum::{extract::State, routing::get, Json, Router};
use crate::alerts::Alert;
use crate::mitigation::MitigationEvent;
use serde::Serialize;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Serialize)]
pub struct TrafficSample {
    pub timestamp: u64,
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceStat {
    pub ip: String,
    pub packets: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PortStat {
    pub port: u16,
    pub packets: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct LiveState {
    pub engine_running: bool,
    pub capture_interface: String,
    pub xdp_enabled: bool,
    pub firewall_enabled: bool,

    pub protected_ips: Vec<String>,
    pub packets_per_second: u64,
    pub bytes_per_second: u64,

    pub traffic_history: Vec<TrafficSample>,

    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,

    pub top_source_ips: Vec<SourceStat>,
    pub top_destination_ports: Vec<PortStat>,
    pub source_concentration: f64,
    pub destination_port_concentration: f64,

    pub anomaly_score: f64,
    pub z_score: f64,

    pub active_blocked_ips: u64,
    pub total_alerts: u64,
    pub critical_alerts: u64,
    pub high_alerts: u64,
    pub medium_alerts: u64,
    pub low_alerts: u64,

    pub xdp_blocks: u64,
    pub firewall_blocks: u64,

    pub mitigation_history: Vec<MitigationEvent>,

    pub recent_alerts: Vec<Alert>,
}

impl Default for LiveState {
    fn default() -> Self {
        Self {
            engine_running: false,
            capture_interface: String::new(),
            xdp_enabled: false,
            firewall_enabled: false,

            protected_ips: Vec::new(),
            packets_per_second: 0,
            bytes_per_second: 0,

            traffic_history: Vec::new(),

            tcp_packets: 0,
            udp_packets: 0,
            icmp_packets: 0,

            top_source_ips: Vec::new(),
            top_destination_ports: Vec::new(),
            source_concentration: 0.0,
            destination_port_concentration: 0.0,

            anomaly_score: 0.0,
            z_score: 0.0,

            active_blocked_ips: 0,
            total_alerts: 0,
            critical_alerts: 0,
            high_alerts: 0,
            medium_alerts: 0,
            low_alerts: 0,

            xdp_blocks: 0,
            firewall_blocks: 0,

            mitigation_history: Vec::new(),

            recent_alerts: Vec::new(),
        }
    }
}

pub type SharedState = Arc<RwLock<LiveState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(LiveState::default()))
}

async fn get_state(State(state): State<SharedState>) -> Json<LiveState> {
    let state = state.read().expect("live state lock poisoned");
    Json(state.clone())
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/api/state", get(get_state))
        .with_state(state)
}
