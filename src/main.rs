use std::io::Read;

use tun::Device;

fn main() {
    let mut config = tun::configure();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut device = tun::create(&config).unwrap();
    println!("device name: {}", device.name());
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = device.read(&mut buf).unwrap();
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(packet) => {
                println!(
                    "{:x?} -> {:x?} {}b of protocol {}",
                    packet.source_addr(),
                    packet.destination_addr(),
                    packet.payload_len(),
                    packet.protocol(),
                );
            }
            Err(e) => {
                println!("not an ipv4 packet: {}", e);
            }
        }
    }
}
