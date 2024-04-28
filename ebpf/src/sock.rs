use aya_ebpf::programs::TcContext;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

/// Represents a pair of sockets involved in a network communication.
pub struct SocketPair {
    /// The source IP address.
    pub src_ip: u32,
    /// The destination IP address.
    pub dst_ip: u32,
    /// The source port number.
    pub src_port: u16,
    /// The destination port number.
    pub dst_port: u16,
}

impl SocketPair {
    /// Loads the socket pair from the given context.
    pub fn load(ctx: &TcContext) -> Result<Self, &'static str> {
        let ip_hdr: Ipv4Hdr = ctx
            .load(EthHdr::LEN)
            .map_err(|_| "failed to load IP header")?;
        let udp_hdr: UdpHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN)
            .map_err(|_| "failed to load UDP header")?;

        Ok(SocketPair {
            src_ip: u32::from_be(ip_hdr.src_addr),
            dst_ip: u32::from_be(ip_hdr.dst_addr),
            src_port: u16::from_be(udp_hdr.source),
            dst_port: u16::from_be(udp_hdr.dest),
        })
    }

    /// Checks if the socket pair represents a query from a DNS server.
    pub fn is_dns_query(&self) -> bool {
        self.dst_port == 53
    }

    /// Checks if the socket pair represents a response from a DNS server.
    pub fn is_dns_response(&self) -> bool {
        self.src_port == 53
    }
}
