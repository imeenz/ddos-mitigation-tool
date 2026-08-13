use pcap::Device;

pub fn list_interfaces() -> Result<Vec<Device>, pcap::Error> {
    let devices = Device::list()?;

    println!("\nAvailable Network Interfaces:");

    for (index, device) in devices.iter().enumerate() {
        println!(
            "{}. {} — {}",
            index + 1,
            device.name,
            device.desc.as_deref().unwrap_or("No description")
        );
    }

    Ok(devices)
}
