#![allow(dead_code)]

mod ip;
mod tcp;
mod tcp_flags;
mod tls;

pub use crate::packet::ip::{IpPacket, IpPayload};
pub use crate::packet::tcp::{TcpPacket, TcpPayload};
pub use crate::packet::tls::TlsPacket;
use pnet::packet::Packet as NetPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use rtest::test_cases;

#[cfg(test)]
pub use crate::packet::tcp_flags::TcpFlags;

#[derive(Debug, PartialEq)]
pub enum Packet {
    Ip(IpPacket),
}

impl Packet {
    pub fn parse(data: &[u8]) -> Option<Packet> {
        let eth_pkt = EthernetPacket::new(data)?;
        match eth_pkt.get_ethertype() {
            EtherTypes::Ipv4 => ip::parse4(eth_pkt.payload()).map(Packet::Ip),
            EtherTypes::Ipv6 => ip::parse6(eth_pkt.payload()).map(Packet::Ip),
            _ => None,
        }
    }
}

test_cases!(parse => vars{
    use std::net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr
    };

    const EMPTY_PAYLOAD: &[u8] = &[];
    const INCORRECT_PAYLOAD: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x00, 0x00
    ];
    const IPV4_PAYLOAD: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x08, 0x00, 0x45, 0xc0,
        0x00, 0x18, 0xe3, 0x71, 0x00, 0x00, 0xff, 0xff,
        0x31, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
    ];
    const INVALID_IPV4_PAYLOAD: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x08, 0x00,
    ];
    const IPV6_PAYLOAD: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x08, 0xff, 0xff, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0f, 0x0e,
        0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06,
        0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    const INVALID_IPV6_PAYLOAD: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x86, 0xdd,
    ];
}, cases{
    struct TestCase{
        payload:  &'static [u8],
        pkt: Option<Packet>,
    }
}[
    case(empty_payload, TestCase{
        payload: EMPTY_PAYLOAD,
        pkt: None,
    }),
    case(incorrect_payload, TestCase{
        payload: INCORRECT_PAYLOAD,
        pkt: None,
    }),
    case(ipv4_payload, TestCase{
        payload: IPV4_PAYLOAD,
        pkt: Some(Packet::Ip(IpPacket {
            src: IpAddr::V4(Ipv4Addr::new(0x01, 0x02, 0x03, 0x04)),
            dst: IpAddr::V4(Ipv4Addr::new(0x05, 0x06, 0x07, 0x08)),
            payload: IpPayload::Other(IPV4_PAYLOAD[34..].to_vec()),
        }))
    }),
    case(invalid_ipv4_payload, TestCase{
        payload: INVALID_IPV4_PAYLOAD,
        pkt: None,
    }),
    case(ipv6_payload, TestCase{
        payload: IPV6_PAYLOAD,
        pkt: Some(Packet::Ip(IpPacket {
            src: IpAddr::V6(Ipv6Addr::new(0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0a0b, 0x0c0d, 0x0e0f)),
            dst: IpAddr::V6(Ipv6Addr::new(0x0f0e, 0x0d0c, 0x0b0a, 0x0908, 0x0706, 0x0504, 0x0302, 0x0100)),
            payload: IpPayload::Other(IPV6_PAYLOAD[54..].to_vec()),
        }))
    }),
    case(invalid_ipv6_payload, TestCase{
        payload: INVALID_IPV6_PAYLOAD,
        pkt: None,
    })
] => |tc: TestCase| {
    let pkt = Packet::parse(tc.payload);
    assert_eq!(tc.pkt, pkt);
});
