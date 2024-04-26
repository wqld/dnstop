#![no_std]
#![no_main]

use core::{
    mem::{self, zeroed},
    str::from_utf8_unchecked,
};

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
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
    let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

    let src_ip = u32::from_be(ip_hdr.src_addr);
    let src_port = u16::from_be(udp_hdr.source);

    if src_port == 53 {
        info!(&ctx, "response from {:i}:{}", src_ip, src_port);

        let dns_hdr: DnsHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
            .map_err(|_| ())?;

        info!(
            &ctx,
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

        info!(&ctx, "qr: {}, opcode: {}", qr, opcode);
    }
    Ok(TC_ACT_PIPE)
}

fn handle_udp_egress(ctx: TcContext) -> Result<i32, ()> {
    let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

    let src_ip = u32::from_be(ip_hdr.src_addr);
    let src_port = u16::from_be(udp_hdr.source);
    let dst_ip = u32::from_be(ip_hdr.dst_addr);
    let dst_port = u16::from_be(udp_hdr.dest);

    if dst_port == 53 {
        info!(
            &ctx,
            "request dns query from {:i}:{} to {:i}:{}", src_ip, src_port, dst_ip, dst_port
        );

        let dns_hdr: DnsHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
            .map_err(|_| ())?;

        info!(
            &ctx,
            "DNS request id: {}, flag: {}, qc: {}, ac: {}, authc: {}, addc: {}",
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

        info!(&ctx, "query: {}, opcode: {}", qr, opcode);

        if (qr != 0) || (opcode != 0) {
            return Ok(TC_ACT_PIPE);
        }

        let dns_query_start = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DnsHdr::LEN;
        let dns_query_end = ctx.len() as usize;

        info!(
            &ctx,
            "dns query start: {}, end: {}", dns_query_start, dns_query_end
        );

        let mut dns_query = DnsQuery {
            record_type: 0,
            class: 0,
            name: unsafe { zeroed() },
        };

        let mut cur_buf_idx = dns_query_start;
        let mut name_idx = 0;
        let mut cur_label_len = None;
        let mut cur_label_idx = 0;

        while name_idx < MAX_DNS_NAME_LENGTH {
            if cur_buf_idx + 1 > dns_query_end {
                error!(&ctx, "boundary exceeded while parsing DNS query name");
                break;
            }

            let c: u8 = ctx.load(cur_buf_idx).map_err(|_| ())?;

            if c == 0 {
                if (cur_buf_idx + 5) > dns_query_end {
                    error!(
                        &ctx,
                        "boundary exceeded while retrieving DNS record type and class"
                    );
                } else {
                    let record_type: u16 = ctx.load(cur_buf_idx + 1).map_err(|_| ())?;
                    let class: u16 = ctx.load(cur_buf_idx + 3).map_err(|_| ())?;

                    dns_query.record_type = u16::from_be(record_type);
                    dns_query.class = u16::from_be(class);
                }

                break;
            }

            if let Some(label_len) = cur_label_len {
                dns_query.name[name_idx] = c;
                cur_label_idx += 1;
                name_idx += 1;

                if cur_label_idx == label_len as usize {
                    dns_query.name[name_idx] = b'.';
                    cur_label_len = None;
                    cur_label_idx = 0;
                    name_idx += 1;
                }
            } else {
                cur_label_len = Some(c);
            }

            cur_buf_idx += 1;
        }

        info!(
            &ctx,
            "domain name: {}, record type: {}, class: {}",
            unsafe { from_utf8_unchecked(&dns_query.name[..name_idx]) },
            dns_query.record_type,
            dns_query.class
        );
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const RAW_QUERY: u16 = 1 << 15;
const RAW_OPCODE_SHIFT: u16 = 11;
const RAW_OPCODE_MASK: u16 = 0b1111;

const MAX_DNS_NAME_LENGTH: usize = 256;

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

impl DnsHdr {
    pub const LEN: usize = mem::size_of::<DnsHdr>();
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsQuery {
    record_type: u16,
    class: u16,
    name: [u8; MAX_DNS_NAME_LENGTH],
}
