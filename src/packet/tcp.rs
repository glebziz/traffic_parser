use crate::packet::tcp_flags::TcpFlags;
use crate::packet::tls;
use crate::packet::tls::TlsPacket;
use pnet::packet::{Packet, tcp};
use rtest::test_cases;

#[derive(Debug, PartialEq)]
pub enum TcpPayload {
    Tls(TlsPacket),
    Other(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub struct TcpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: TcpFlags,
    pub seq_num: u32,
    pub payload: TcpPayload,
}

pub fn parse(payload: &[u8]) -> Option<TcpPacket> {
    let tcp_pkt = tcp::TcpPacket::new(payload)?;

    Some(TcpPacket {
        src_port: tcp_pkt.get_source(),
        dst_port: tcp_pkt.get_destination(),
        flags: TcpFlags::from(tcp_pkt.get_flags()),
        seq_num: tcp_pkt.get_sequence(),
        payload: parse_payload(tcp_pkt.payload()),
    })
}

fn parse_payload(payload: &[u8]) -> TcpPayload {
    if let Some(tls_pkt) = tls::parse(payload) {
        return TcpPayload::Tls(tls_pkt);
    }

    TcpPayload::Other(payload.to_vec())
}

test_cases!(parse => vars{
    const EMPTY_PAYLOAD: &[u8] = &[];
    const TCP_PAYLOAD: &[u8] = &[
        0x05, 0x39, 0xd6, 0x4c, 0x66, 0xc5, 0x66, 0x27,
        0xfd, 0xc5, 0x6d, 0xad, 0x80, 0x18, 0x00, 0xe0,
        0xf1, 0x25, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x11, 0x73, 0xca, 0x35, 0xe2, 0x6f, 0x35, 0x83,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
}, cases{
    struct TestCase{
        payload: &'static [u8],
        tcp_pkt: Option<TcpPacket>,
    }
}[
    case(empty_payload,  TestCase{
        payload: EMPTY_PAYLOAD,
        tcp_pkt: None
    }),
    case(tcp_payload,  TestCase{
        payload: TCP_PAYLOAD,
        tcp_pkt: Some(TcpPacket{
            src_port: 1337,
            dst_port: 54860,
            flags: TcpFlags::from(0x18),
            seq_num: 1724212775,
            payload: TcpPayload::Other(TCP_PAYLOAD[32..].to_vec()),
        })
    })
] => |tc: TestCase| {
    let tcp_pkt = parse(tc.payload);
    assert_eq!(tc.tcp_pkt, tcp_pkt);
});

test_cases!(parse_payload => vars{
    const TLS_PAYLOAD: &[u8] = &[0x14, 0x00, 0x00, 0x00, 0x00];
    const OTHER_PAYLOAD: &[u8] = &[0x00, 0x01, 0x02, 0x03];
}, cases{
    struct TestCase{
        payload: &'static [u8],
        tcp_payload: TcpPayload,
    }
}[
    case(tls_payload,  TestCase{
        payload: TLS_PAYLOAD,
        tcp_payload: TcpPayload::Tls(TlsPacket::Other)
    }),
    case(other_payload,  TestCase{
        payload: OTHER_PAYLOAD,
        tcp_payload: TcpPayload::Other(OTHER_PAYLOAD.to_vec())
    })
] => |tc: TestCase| {
    let p = parse_payload(tc.payload);
    assert_eq!(tc.tcp_payload, p);
});
