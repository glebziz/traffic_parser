use crate::packet::tcp;
use crate::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use rtest::test_cases;
use std::net::IpAddr;

#[derive(Debug, PartialEq)]
pub enum IpPayload {
    Tcp(TcpPacket),
    Other(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub struct IpPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub payload: IpPayload,
}

pub fn parse4(payload: &[u8]) -> Option<IpPacket> {
    let ip_pkt = Ipv4Packet::new(payload)?;

    Some(IpPacket {
        src: IpAddr::V4(ip_pkt.get_source()),
        dst: IpAddr::V4(ip_pkt.get_destination()),
        payload: parse_payload(ip_pkt.get_next_level_protocol(), ip_pkt.payload()),
    })
}

pub fn parse6(payload: &[u8]) -> Option<IpPacket> {
    let ip_pkt = Ipv6Packet::new(payload)?;

    Some(IpPacket {
        src: IpAddr::V6(ip_pkt.get_source()),
        dst: IpAddr::V6(ip_pkt.get_destination()),
        payload: parse_payload(ip_pkt.get_next_header(), ip_pkt.payload()),
    })
}

pub fn parse_payload(next: IpNextHeaderProtocol, payload: &[u8]) -> IpPayload {
    match next {
        IpNextHeaderProtocols::Tcp => match tcp::parse(payload) {
            Some(tcp_pkt) => IpPayload::Tcp(tcp_pkt),
            None => IpPayload::Other(payload.to_vec()),
        },
        _ => IpPayload::Other(payload.to_vec()),
    }
}

test_cases!(parse4 => vars{
    use std::net::Ipv4Addr;

    const EMPTY_PAYLOAD: &[u8] = &[];
    const INCORRECT_PAYLOAD: &[u8] = &[0x01, 0x02, 0x03, 0x04];
    const IP_PAYLOAD: &[u8] = &[
        0x45, 0xc0, 0x00, 0x18, 0xe3, 0x71, 0x00, 0x00,
        0xff, 0xff, 0x31, 0x42, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
    ];
}, cases{
    struct TestCase{
        payload: &'static [u8],
        pkt: Option<IpPacket>,
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
    case(ip_payload, TestCase{
        payload: IP_PAYLOAD,
        pkt: Some(IpPacket {
            src: IpAddr::V4(Ipv4Addr::new(0x01, 0x02, 0x03, 0x04)),
            dst: IpAddr::V4(Ipv4Addr::new(0x05, 0x06, 0x07, 0x08)),
            payload: IpPayload::Other(IP_PAYLOAD[20..].to_vec()),
        })
    })
] => |tc: TestCase| {
    let pkt = parse4(tc.payload);
    assert_eq!(tc.pkt, pkt);
});

test_cases!(parse6 => vars{
    use std::net::Ipv6Addr;

    const EMPTY_PAYLOAD: &[u8] = &[];
    const INCORRECT_PAYLOAD: &[u8] = &[0x01, 0x02, 0x03, 0x04];
    const IP_PAYLOAD: &[u8] = &[
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0xff, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
}, cases{
    struct TestCase{
        payload: &'static [u8],
        pkt: Option<IpPacket>,
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
    case(ip_payload, TestCase{
        payload: IP_PAYLOAD,
        pkt: Some(IpPacket {
            src: IpAddr::V6(Ipv6Addr::new(0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0a0b, 0x0c0d, 0x0e0f)),
            dst: IpAddr::V6(Ipv6Addr::new(0x0f0e, 0x0d0c, 0x0b0a, 0x0908, 0x0706, 0x0504, 0x0302, 0x0100)),
            payload: IpPayload::Other(IP_PAYLOAD[40..].to_vec()),
        })
    })
] => |tc: TestCase| {
    let pkt = parse6(tc.payload);
    assert_eq!(tc.pkt, pkt);
});

test_cases!(parse_payload => vars{
    use crate::packet::tcp_flags::TcpFlags;
    use crate::packet::tcp::TcpPayload;

    const EMPTY_PAYLOAD: &[u8] = &[];
    const INCORRECT_TCP_PAYLOAD: &[u8] = &[0x01, 0x02, 0x03, 0x04];
    const TCP_PAYLOAD: &[u8] = &[
        0x05, 0x39, 0xd6, 0x4c, 0x66, 0xc5, 0x66, 0x27,
        0xfd, 0xc5, 0x6d, 0xad, 0x80, 0x18, 0x00, 0xe0,
        0xf1, 0x25, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x11, 0x73, 0xca, 0x35, 0xe2, 0x6f, 0x35, 0x83,
    ];
}, cases{
    struct TestCase{
        next: IpNextHeaderProtocol,
        payload: &'static [u8],
        ip_payload: IpPayload,
    }
}[
    case(empty_payload, TestCase{
        next: IpNextHeaderProtocols::Reserved,
        payload: EMPTY_PAYLOAD,
        ip_payload: IpPayload::Other(vec![]),
    }),
    case(incorrect_tcp_payload, TestCase{
        next: IpNextHeaderProtocols::Tcp,
        payload: INCORRECT_TCP_PAYLOAD,
        ip_payload: IpPayload::Other(INCORRECT_TCP_PAYLOAD.to_vec()),
    }),
    case(tcp_payload, TestCase{
       next: IpNextHeaderProtocols::Tcp,
        payload: TCP_PAYLOAD,
        ip_payload: IpPayload::Tcp(TcpPacket{
            src_port: 1337,
            dst_port: 54860,
            flags: TcpFlags::from(0x18),
            seq_num: 1724212775,
            payload: TcpPayload::Other(vec![]),
        })
    })
] => |tc: TestCase| {
    let payload = parse_payload(tc.next, tc.payload);
    assert_eq!(tc.ip_payload, payload);
});
