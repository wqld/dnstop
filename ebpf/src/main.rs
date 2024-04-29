#![no_std]
#![no_main]

mod dns;
mod sock;

use core::str::from_utf8_unchecked;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use sock::SocketPair;

use crate::dns::{DnsHdr, DnsQuery, MAX_DNS_NAME_LENGTH};

#[map]
static mut DNS_QUERY: HashMap<u16, DnsQuery> = HashMap::with_max_entries(128, 0);

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
    match load_eth_and_ip_headers(ctx) {
        Ok((_, ipv4hdr)) => match ipv4hdr.proto {
            IpProto::Udp => handle_udp_ingress(ctx),
            _ => Ok(TC_ACT_PIPE),
        },
        _ => Ok(TC_ACT_PIPE),
    }
}

fn try_egress(ctx: &TcContext) -> Result<i32, &'static str> {
    match load_eth_and_ip_headers(ctx) {
        Ok((_, ipv4hdr)) => match ipv4hdr.proto {
            IpProto::Udp => handle_udp_egress(ctx),
            _ => Ok(TC_ACT_PIPE),
        },
        _ => Ok(TC_ACT_PIPE),
    }
}

fn load_eth_and_ip_headers(ctx: &TcContext) -> Result<(EthHdr, Ipv4Hdr), &'static str> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| "failed to load Ethernet header")?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx
                .load(EthHdr::LEN)
                .map_err(|_| "failed to load IP header")?;
            Ok((eth_hdr, ipv4hdr))
        }
        _ => Err("not IPv4"),
    }
}

fn handle_udp_ingress(ctx: &TcContext) -> Result<i32, &'static str> {
    let socket_pair = SocketPair::load(ctx)?;

    if socket_pair.is_dns_response() {
        let dns_hdr = DnsHdr::load(ctx)?;

        let dns_query = unsafe {
            match DNS_QUERY.get(&dns_hdr.id) {
                Some(query) => query,
                None => return Ok(TC_ACT_PIPE),
            }
        };

        info!(
            ctx,
            "{}: ID={} DNS_NAME={} DNS_TYPE={} DNS_CLASS={}",
            dns_hdr.rcode_to_str(),
            dns_hdr.id,
            unsafe { from_utf8_unchecked(&dns_query.name[..MAX_DNS_NAME_LENGTH]) },
            dns_query.record_type_to_str(),
            dns_query.class_to_str()
        );

        unsafe {
            DNS_QUERY
                .remove(&dns_hdr.id)
                .expect("failed to remove DNS query");
        }
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

        DnsQuery::process(ctx, &dns_hdr)?;

        let dns_query = unsafe {
            match DNS_QUERY.get(&dns_hdr.id) {
                Some(query) => query,
                None => return Ok(TC_ACT_PIPE),
            }
        };

        info!(
            ctx,
            "REQ: ID={} SRC={:i}:{} DST={:i}:{} DNS_NAME={} DNS_TYPE={} DNS_CLASS={}",
            dns_hdr.id,
            socket_pair.src_ip,
            socket_pair.src_port,
            socket_pair.dst_ip,
            socket_pair.dst_port,
            unsafe { from_utf8_unchecked(&dns_query.name[..MAX_DNS_NAME_LENGTH]) },
            dns_query.record_type_to_str(),
            dns_query.class_to_str(),
        );
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
