use std::{collections::HashMap, io::Read, net::Ipv4Addr};

mod tcp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Quad {
    src: (Ipv4Addr, u16),
    dest: (Ipv4Addr, u16),
}

fn main() {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut config = tun::configure();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut device = tun::create(&config).unwrap();
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = device.read(&mut buf).unwrap();
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                if ip_header.protocol() != 0x06 {
                    // not tcp
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[4 + ip_header.slice().len()..nbytes],
                ) {
                    Ok(tcp_header) => {
                        // The actual data starts after the 4 bytes of the ethernet header,
                        // the ip header, and the tcp header
                        let data_start = 4 + ip_header.slice().len() + tcp_header.slice().len();
                        match connections
                            .entry(Quad {
                                src: (src, tcp_header.source_port()),
                                dest: (dst, tcp_header.destination_port()),
                            })
                            .or_default()
                            .on_packet(
                                &mut device,
                                &ip_header,
                                &tcp_header,
                                &buf[data_start..nbytes],
                            ) {
                            Ok(written_bytes) => println!("written bytes: {}", written_bytes),
                            Err(e) => println!("error: {}", e),
                        }
                    }
                    Err(e) => {
                        println!("not a tcp packet: {}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                println!("not an ipv4 packet: {}", e);
            }
        }
    }
}
