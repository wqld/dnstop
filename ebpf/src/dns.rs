use core::mem::{size_of, zeroed};

use aya_ebpf::programs::TcContext;
use aya_log_ebpf::error;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

use crate::DNS_QUERY;

pub const MAX_DNS_NAME_LENGTH: usize = 256;

pub const RAW_QUERY: u16 = 1 << 15;
const RAW_OPCODE_SHIFT: u16 = 11;
const RAW_OPCODE_MASK: u16 = 0b1111;
// const RAW_AA: u16 = 1 << 10;
// const RAW_TC: u16 = 1 << 9;
// const RAW_RD: u16 = 1 << 8;
// const RAW_RA: u16 = 1 << 7;
const RAW_RCODE_SHIFT: u16 = 0;
const RAW_RCODE_MASK: u16 = 0b1111;

const DNS_PAYLOAD_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DnsHdr::LEN;
const RECORD_TYPE_OFFSET: usize = 1;
const CLASS_OFFSET: usize = 3;

/// DNS header structure
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
    /// Length of DNS header
    pub const LEN: usize = size_of::<DnsHdr>();

    /// Load DNS header from context
    pub fn load(ctx: &TcContext) -> Result<DnsHdr, &'static str> {
        let mut dns_hdr: DnsHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
            .map_err(|_| "failed to load DNS header")?;

        dns_hdr.convert_endian();
        Ok(dns_hdr)
    }

    /// Check if the DNS header is a standard query
    pub fn standard_query(&self) -> bool {
        self.query() == 0 && self.opcode() == 0
    }

    /// Convert response code to string
    pub fn rcode_to_str(&self) -> &'static str {
        match self.rcode() {
            0 => "OK",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "UNKNOWN",
        }
    }

    fn query(&self) -> u16 {
        self.flags & RAW_QUERY
    }

    fn opcode(&self) -> u16 {
        (self.flags >> RAW_OPCODE_SHIFT) & RAW_OPCODE_MASK
    }

    fn rcode(&self) -> u16 {
        (self.flags >> RAW_RCODE_SHIFT) & RAW_RCODE_MASK
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

/// DNS query structure
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsQuery {
    pub record_type: u16,
    pub class: u16,
    pub name: [u8; MAX_DNS_NAME_LENGTH],
}

impl DnsQuery {
    /// Process DNS query from context
    pub fn process(ctx: &TcContext, dns_hdr: &DnsHdr) -> Result<Self, &'static str> {
        let buf_len = ctx.len() as usize;

        let mut dns_query = DnsQuery {
            record_type: 0,
            class: 0,
            name: unsafe { zeroed() },
        };

        dns_query.parse(ctx, buf_len)?;

        unsafe {
            DNS_QUERY
                .insert(&dns_hdr.id, &dns_query, 0)
                .expect("failed to insert DNS query");
        }

        Ok(dns_query)
    }

    /// Convert record type to string
    pub fn record_type_to_str(&self) -> &'static str {
        match self.record_type {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            255 => "ANY",
            _ => "UNKNOWN",
        }
    }

    /// Convert class to string
    pub fn class_to_str(&self) -> &'static str {
        match self.class {
            1 => "IN",
            2 => "CS",
            3 => "CH",
            4 => "HS",
            _ => "UNKNOWN",
        }
    }

    fn parse(&mut self, ctx: &TcContext, buf_len: usize) -> Result<(), &'static str> {
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
                .map_err(|_| "failed to read DNS query name byte")?;

            if c == 0 {
                self.name[name_idx - 1] = c;
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

        if (DNS_PAYLOAD_OFFSET + name_idx + 5) > buf_len {
            error!(
                ctx,
                "boundary exceeded while retrieving DNS record type and class"
            );
        } else {
            let record_type: u16 = ctx
                .load(DNS_PAYLOAD_OFFSET + name_idx + RECORD_TYPE_OFFSET)
                .map_err(|_| "failed to read record type")?;
            let class: u16 = ctx
                .load(DNS_PAYLOAD_OFFSET + name_idx + CLASS_OFFSET)
                .map_err(|_| "failed to read class")?;

            self.record_type = u16::from_be(record_type);
            self.class = u16::from_be(class);
        }

        Ok(())
    }
}
