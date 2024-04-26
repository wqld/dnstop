use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

pub struct SocketPair {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SocketPair {
    pub fn load(ctx: &TcContext) -> Result<Self, &'static str> {
        let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).expect("failed to load IP header");
        let udp_hdr: UdpHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN)
            .expect("failed to load UDP header");

        Ok(SocketPair {
            src_ip: u32::from_be(ip_hdr.src_addr),
            dst_ip: u32::from_be(ip_hdr.dst_addr),
            src_port: u16::from_be(udp_hdr.source),
            dst_port: u16::from_be(udp_hdr.dest),
        })
    }

    pub fn print(&self, ctx: &TcContext) {
        info!(
            ctx,
            "dns packet from {:i}:{} to {:i}:{}",
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port
        );
    }

    pub fn is_dns_query(&self) -> bool {
        self.dst_port == 53
    }

    pub fn is_dns_response(&self) -> bool {
        self.src_port == 53
    }
}
