use core::{
    mem::{size_of, zeroed},
    str::from_utf8_unchecked,
};

use aya_ebpf::programs::TcContext;
use aya_log_ebpf::{error, info};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

use crate::sock::SocketPair;

pub const MAX_DNS_NAME_LENGTH: usize = 256;

pub const RAW_QUERY: u16 = 1 << 15;
const RAW_OPCODE_SHIFT: u16 = 11;
const RAW_OPCODE_MASK: u16 = 0b1111;

const DNS_PAYLOAD_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DnsHdr::LEN;
const RECORD_TYPE_OFFSET: usize = 1;
const CLASS_OFFSET: usize = 3;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsHdr {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHdr {
    pub const LEN: usize = size_of::<DnsHdr>();

    pub fn load(ctx: &TcContext) -> Result<DnsHdr, &'static str> {
        let mut dns_hdr: DnsHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
            .expect("failed to load DNS header");

        dns_hdr.convert_endian();
        Ok(dns_hdr)
    }

    pub fn standard_query(&self) -> bool {
        self.query() == 0 && self.opcode() == 0
    }

    pub fn query(&self) -> u16 {
        self.flags & RAW_QUERY
    }

    pub fn opcode(&self) -> u16 {
        (self.flags >> RAW_OPCODE_SHIFT) & RAW_OPCODE_MASK
    }

    fn convert_endian(&mut self) {
        self.id = u16::from_be(self.id);
        self.flags = u16::from_be(self.flags);
        self.question_count = u16::from_be(self.question_count);
        self.answer_count = u16::from_be(self.answer_count);
        self.authority_count = u16::from_be(self.authority_count);
        self.additional_count = u16::from_be(self.additional_count);
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsQuery {
    pub record_type: u16,
    pub class: u16,
    pub name: [u8; MAX_DNS_NAME_LENGTH],
    pub name_len: usize,
}

impl DnsQuery {
    pub fn process_request(
        ctx: &TcContext,
        dns_hdr: &DnsHdr,
        socket_pair: &SocketPair,
    ) -> Result<(), &'static str> {
        let buf_len = ctx.len() as usize;

        let mut dns_query = DnsQuery {
            record_type: 0,
            class: 0,
            name: unsafe { zeroed() },
            name_len: 0,
        };

        dns_query.parse_name(ctx, buf_len)?;
        dns_query.parse_record_type_and_class(ctx, buf_len)?;
        dns_query.print(ctx, dns_hdr, socket_pair);
        Ok(())
    }

    pub fn print(&self, ctx: &TcContext, dns_hdr: &DnsHdr, socket_pair: &SocketPair) {
        info!(
            ctx,
            "-> ID={} SRC={:i}:{} DST={:i}:{} DNS_NAME={} DNS_TYPE={} DNS_CLASS={}",
            dns_hdr.id,
            socket_pair.src_ip,
            socket_pair.src_port,
            socket_pair.dst_ip,
            socket_pair.dst_port,
            unsafe { from_utf8_unchecked(&self.name[..self.name_len]) },
            self.record_type,
            self.class
        );
    }

    fn parse_name(&mut self, ctx: &TcContext, buf_len: usize) -> Result<(), &'static str> {
        let mut cur_buf_idx = DNS_PAYLOAD_OFFSET;
        let mut name_idx = 0;
        let mut cur_label_len = None;
        let mut cur_label_idx = 0;

        while name_idx < MAX_DNS_NAME_LENGTH {
            if cur_buf_idx + 1 > buf_len {
                error!(ctx, "boundary exceeded while parsing DNS query name");
                break;
            }

            let c: u8 = ctx
                .load(cur_buf_idx)
                .expect("failed to read DNS query name byte");

            if c == 0 {
                break;
            }

            if let Some(label_len) = cur_label_len {
                self.name[name_idx] = c;
                cur_label_idx += 1;
                name_idx += 1;

                if cur_label_idx == label_len as usize {
                    self.name[name_idx] = b'.';
                    cur_label_len = None;
                    cur_label_idx = 0;
                    name_idx += 1;
                }
            } else {
                cur_label_len = Some(c);
            }

            cur_buf_idx += 1;
        }

        self.name_len = name_idx;
        Ok(())
    }

    fn parse_record_type_and_class(
        &mut self,
        ctx: &TcContext,
        buf_len: usize,
    ) -> Result<(), &'static str> {
        if (DNS_PAYLOAD_OFFSET + self.name_len + 5) > buf_len {
            error!(
                ctx,
                "boundary exceeded while retrieving DNS record type and class"
            );
        } else {
            let record_type: u16 = ctx
                .load(DNS_PAYLOAD_OFFSET + self.name_len + RECORD_TYPE_OFFSET)
                .expect("failed to read record type");
            let class: u16 = ctx
                .load(DNS_PAYLOAD_OFFSET + self.name_len + CLASS_OFFSET)
                .expect("failed to read class");

            self.record_type = u16::from_be(record_type);
            self.class = u16::from_be(class);
        }

        Ok(())
    }
}
