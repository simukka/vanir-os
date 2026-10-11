//! A look at each received frame before smoltcp sees it: just enough parsing to count what
//! smoltcp would drop silently, and to apply the limits that must act before a socket is
//! touched.

/// The parts of an IPv4 packet we look at.
pub struct Ipv4<'a> {
    pub src: [u8; 4],
    pub proto: u8,
    pub checksum_ok: bool,
    pub payload: &'a [u8],
}

/// The parts of a TCP header we look at.
pub struct Tcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}

pub const TCP_SYN: u8 = 2;
pub const TCP_RST: u8 = 4;
pub const TCP_ACK: u8 = 16;

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The IPv4 packet in an Ethernet frame, if it is one.
pub fn ipv4(frame: &[u8]) -> Option<Ipv4<'_>> {
    if frame.len() < 34 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &frame[14..];
    let header = ((ip[0] & 0xf) as usize) * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ip[0] >> 4 != 4 || header < 20 || total < header || total > ip.len() {
        return None;
    }
    Some(Ipv4 {
        src: ip[12..16].try_into().unwrap(),
        proto: ip[9],
        checksum_ok: checksum(&ip[..header]) == 0,
        payload: &ip[header..total],
    })
}

/// The TCP header at the start of an IPv4 payload.
pub fn tcp(payload: &[u8]) -> Option<Tcp> {
    (payload.len() >= 20).then(|| Tcp {
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        flags: payload[13],
    })
}
