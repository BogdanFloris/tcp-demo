use std::io;
use std::io::Write;

enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default)]
struct SendSequenceSpace {
    /// send unacknowledged
    una: usize,
    /// send next
    nxt: usize,
    /// send window
    wnd: usize,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: usize,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default)]
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Default for Connection {
    fn default() -> Self {
        Connection {
            state: State::Listen,
            send: SendSequenceSpace::default(),
            recv: RecvSequenceSpace::default(),
        }
    }
}

impl Connection {
    pub fn on_packet(
        &mut self,
        device: &mut tun::platform::Device,
        ip_header: &etherparse::Ipv4HeaderSlice,
        tcp_header: &etherparse::TcpHeaderSlice,
        _data: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        let iss = 0;
        let wnd = 1024;
        match self.state {
            State::Closed => return Ok(0),
            State::Listen => {
                if !tcp_header.syn() {
                    // Only expected a SYN packet
                    return Ok(0);
                }
                // Establish connection by sending SYN-ACK
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    iss,
                    wnd,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                let ip = etherparse::Ipv4Header::new(
                    0,
                    64,
                    etherparse::IpNumber::Tcp as u8,
                    ip_header.destination(),
                    ip_header.source(),
                );
                // write out the headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    ip.write(&mut unwritten).unwrap();
                    syn_ack.write(&mut unwritten).unwrap();
                    unwritten.len()
                };
                device.write(&buf[..unwritten])
            }
            State::SynRcvd => return Ok(0),
            State::Estab => return Ok(0),
        }
    }
}
