use aya::maps::{HashMap, MapData};
use std::net::Ipv4Addr;

const BLOCKED_IPS_PIN: &str = "/sys/fs/bpf/ddos-mitigation/blocked_ips";

pub struct XdpBlocker {
    map: HashMap<MapData, u32, u8>,
}

impl XdpBlocker {
    pub fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let map_data = MapData::from_pin(BLOCKED_IPS_PIN)?;
        let map = HashMap::try_from(aya::maps::Map::from_map_data(map_data)?)?;

        Ok(Self { map })
    }

    pub fn block(&mut self, ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
        self.map.insert(u32::from(ip).to_be(), 1, 0)?;
        Ok(())
    }

    pub fn unblock(&mut self, ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
        let key = u32::from(ip).to_be();
        let _ = self.map.remove(&key);
        Ok(())
    }
}
