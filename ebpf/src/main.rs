#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[classifier]
pub fn ingress(ctx: TcContext) -> i32 {
    match try_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn egress(ctx: TcContext) -> i32 {
    match try_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_ingress(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            match ipv4hdr.proto {
                IpProto::Udp => handle_udp_ingress(ctx),
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

fn try_egress(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            match ipv4hdr.proto {
                IpProto::Udp => handle_udp_egress(ctx),
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

fn handle_udp_ingress(ctx: TcContext) -> Result<i32, ()> {
    let (src_ip, src_port, dst_ip, dst_port) = get_socket_pair(&ctx)?;

    if src_port == 53 {
        let _ = parse_dns(&ctx)?;
    }
    Ok(TC_ACT_PIPE)
}

fn handle_udp_egress(ctx: TcContext) -> Result<i32, ()> {
    let (src_ip, src_port, dst_ip, dst_port) = get_socket_pair(&ctx)?;

    if dst_port == 53 {
        let _ = parse_dns(&ctx)?;
    }

    Ok(TC_ACT_PIPE)
}

fn get_socket_pair(ctx: &TcContext) -> Result<(u32, u16, u32, u16), ()> {
    let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

    let src_ip = u32::from_be(ip_hdr.src_addr);
    let src_port = u16::from_be(udp_hdr.source);
    let dst_ip = u32::from_be(ip_hdr.dst_addr);
    let dst_port = u16::from_be(udp_hdr.dest);

    info!(
        ctx,
        "from {:i}:{} to {:i}:{}", src_ip, src_port, dst_ip, dst_port
    );

    Ok((src_ip, src_port, dst_ip, dst_port))
}

fn parse_dns(ctx: &TcContext) -> Result<(u16, u16), ()> {
    let dns_hdr: DnsHdr = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
        .map_err(|_| ())?;

    info!(
        ctx,
        "DNS response id: {}, flag: {}, qc: {}, ac: {}, authc: {}, addc: {}",
        u16::from_be(dns_hdr.id),
        u16::from_be(dns_hdr.flags),
        u16::from_be(dns_hdr.question_count),
        u16::from_be(dns_hdr.answer_count),
        u16::from_be(dns_hdr.authority_count),
        u16::from_be(dns_hdr.additional_count)
    );

    let flags = u16::from_be(dns_hdr.flags);
    let qr = flags & RAW_QUERY;
    let opcode = (flags >> RAW_OPCODE_SHIFT) & RAW_OPCODE_MASK;

    info!(ctx, "qr: {}, opcode: {}", qr, opcode);

    Ok((qr, opcode))
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const RAW_QUERY: u16 = 1 << 15;
const RAW_OPCODE_SHIFT: u16 = 11;
const RAW_OPCODE_MASK: u16 = 0b1111;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsHdr {
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}
