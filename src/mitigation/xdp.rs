use aya::{
    maps::{HashMap, MapData},
    programs::{
        xdp::{Xdp, XdpLinkId, XdpMode},
        Program,
    },
    EbpfLoader,
};
use std::{
    net::Ipv4Addr,
    path::Path,
};

const BLOCKED_IPS_PIN: &str = "/sys/fs/bpf/ddos-mitigation/blocked_ips";
const XDP_PROGRAM_PATH: &str = "ebpf/xdp_test.o";
const XDP_PROGRAM_NAME: &str = "xdp_test";

pub struct XdpBlocker {
    #[allow(dead_code)]
    ebpf: aya::Ebpf,
    #[allow(dead_code)]
    link_id: XdpLinkId,
    map: HashMap<MapData, u32, u8>,
}

impl XdpBlocker {
    pub fn start(interface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pin_dir = Path::new(BLOCKED_IPS_PIN)
            .parent()
            .ok_or("invalid XDP pin path")?;

        std::fs::create_dir_all(pin_dir)?;

        let mut ebpf = EbpfLoader::new()
            .map_pin_path("blocked_ips", Path::new(BLOCKED_IPS_PIN))
            .load_file(XDP_PROGRAM_PATH)?;

        let link_id = {
            let program = ebpf
                .program_mut(XDP_PROGRAM_NAME)
                .ok_or("XDP program 'xdp' not found in eBPF object")?;

            let program: &mut Xdp = program.try_into()?;

            program.load()?;
            program.attach(interface, XdpMode::default())?
        };

        let map_data = MapData::from_pin(BLOCKED_IPS_PIN)?;
        let map =
            HashMap::try_from(aya::maps::Map::from_map_data(map_data)?)?;

        Ok(Self {
            ebpf,
            link_id,
            map,
        })
    }

    pub fn open() -> Result<Self, Box<dyn std::error::Error>> {
        Err("XDP must be started with XdpBlocker::start()".into())
    }

    pub fn block(
        &mut self,
        ip: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.map.insert(u32::from(ip).to_be(), 1, 0)?;
        Ok(())
    }

    pub fn unblock(
        &mut self,
        ip: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = u32::from(ip).to_be();
        let _ = self.map.remove(&key);
        Ok(())
    }
}
