#![no_std]
#![no_main]

mod dns;
mod sock;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use sock::SocketPair;

use crate::dns::{DnsHdr, DnsQuery, RAW_QUERY};

#[classifier]
pub fn ingress(ctx: TcContext) -> i32 {
    match try_ingress(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "error: {}", e);
            TC_ACT_SHOT
        }
    }
}

#[classifier]
pub fn egress(ctx: TcContext) -> i32 {
    match try_egress(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "error: {}", e);
            TC_ACT_SHOT
        }
    }
}

fn try_ingress(ctx: &TcContext) -> Result<i32, &'static str> {
    let eth_hdr: EthHdr = ctx.load(0).expect("failed to load Ethernet header");
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).expect("failed to load IP header");
            match ipv4hdr.proto {
                IpProto::Udp => handle_udp_ingress(ctx),
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

fn try_egress(ctx: &TcContext) -> Result<i32, &'static str> {
    let eth_hdr: EthHdr = ctx.load(0).expect("failed to load Ethernet header");
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).expect("failed to load IP header");
            match ipv4hdr.proto {
                IpProto::Udp => handle_udp_egress(ctx),
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

fn handle_udp_ingress(ctx: &TcContext) -> Result<i32, &'static str> {
    let socket_pair = SocketPair::load(ctx)?;

    if socket_pair.is_dns_response() {
        let dns_hdr = DnsHdr::load(ctx)?;

        if dns_hdr.query() != RAW_QUERY {
            return Ok(TC_ACT_PIPE);
        }

        // DnsQuery::process_request(ctx, &dns_hdr, &socket_pair)?;
    }

    Ok(TC_ACT_PIPE)
}

fn handle_udp_egress(ctx: &TcContext) -> Result<i32, &'static str> {
    let socket_pair = SocketPair::load(ctx)?;

    if socket_pair.is_dns_query() {
        let dns_hdr = DnsHdr::load(ctx)?;

        if !dns_hdr.standard_query() {
            return Ok(TC_ACT_PIPE);
        }

        DnsQuery::process_request(ctx, &dns_hdr, &socket_pair)?;
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
