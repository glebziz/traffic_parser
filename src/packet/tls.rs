use rtest::test_cases;
use std::str::from_utf8;
use tls_parser::{
    TlsClientHelloContents, TlsHandshakeType, TlsMessageHandshake, TlsRecordType,
    parse_tls_extensions, parse_tls_handshake_msg_client_hello,
    parse_tls_handshake_msg_server_hello, parse_tls_record_header,
};

#[derive(Debug, PartialEq)]
pub enum TlsPacket {
    ClientHandshake(Vec<String>),
    ServerHandshake,
    Other,
}

pub fn parse(payload: &[u8]) -> Option<TlsPacket> {
    let payload = match parse_tls_record_header(payload) {
        Ok((payload, hdr)) => match hdr.record_type {
            TlsRecordType::Handshake => payload,
            TlsRecordType::ChangeCipherSpec
            | TlsRecordType::Alert
            | TlsRecordType::ApplicationData
            | TlsRecordType::Heartbeat => {
                return Some(TlsPacket::Other);
            }
            _ => return None,
        },
        _ => return None,
    };

    parse_tls_handshake(payload)
}

fn parse_tls_handshake(payload: &[u8]) -> Option<TlsPacket> {
    if payload.len() < 4 {
        return None;
    }

    let (ht, payload) = (TlsHandshakeType(payload[0]), &payload[4..]);
    match ht {
        TlsHandshakeType::ClientHello => match parse_tls_handshake_msg_client_hello(payload) {
            Ok((_, TlsMessageHandshake::ClientHello(hello))) => Some(parse_client_hello(hello)),
            _ => None,
        },
        TlsHandshakeType::ServerHello => match parse_tls_handshake_msg_server_hello(payload) {
            Ok((_, TlsMessageHandshake::ServerHello(_))) => Some(TlsPacket::ServerHandshake),
            _ => None,
        },
        TlsHandshakeType::HelloRequest
        | TlsHandshakeType::HelloVerifyRequest
        | TlsHandshakeType::NewSessionTicket
        | TlsHandshakeType::EndOfEarlyData
        | TlsHandshakeType::HelloRetryRequest
        | TlsHandshakeType::EncryptedExtensions
        | TlsHandshakeType::Certificate
        | TlsHandshakeType::ServerKeyExchange
        | TlsHandshakeType::CertificateRequest
        | TlsHandshakeType::ServerDone
        | TlsHandshakeType::CertificateVerify
        | TlsHandshakeType::ClientKeyExchange
        | TlsHandshakeType::Finished
        | TlsHandshakeType::CertificateURL
        | TlsHandshakeType::CertificateStatus
        | TlsHandshakeType::KeyUpdate
        | TlsHandshakeType::NextProtocol => Some(TlsPacket::Other),
        _ => None,
    }
}

fn parse_client_hello(hello: TlsClientHelloContents) -> TlsPacket {
    if hello.ext.is_none() {
        return TlsPacket::ClientHandshake(Vec::default());
    }

    let (_, exts) = parse_tls_extensions(hello.ext.unwrap()).unwrap();
    let sni = exts
        .iter()
        .find(|ext| matches!(ext, tls_parser::TlsExtension::SNI(_)));

    let names = match sni {
        Some(tls_parser::TlsExtension::SNI(names)) => Some(names),
        _ => None,
    };

    if names.is_none() {
        return TlsPacket::ClientHandshake(Vec::default());
    }

    TlsPacket::ClientHandshake(
        names
            .unwrap()
            .iter()
            .filter_map(|(_, name)| match from_utf8(name) {
                Ok(host) => Some(host.to_string()),
                _ => None,
            })
            .collect(),
    )
}

test_cases!(parse => vars{
    const EMPTY_PAYLOAD: &[u8] = &[];
    const INVALID_PAYLOAD: &[u8] = &[0x00];
    const NOT_TLS_PAYLOAD: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00];
    const OTHER_TLS_PAYLOAD: &[u8] = &[0x14, 0x00, 0x00, 0x00, 0x00];
    const INVALID_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x00];
    const OTHER_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x04, // tls Handshake
        0x00, 0x00, 0x00, 0x00 // hello
    ];
    const CLIENT_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x2c, // tls Handshake
        0x01, 0x00, 0x00, 0x28, 0x03, 0x03, // client hello
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    const SERVER_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x2c, // tls Handshake
        0x02, 0x00, 0x00, 0x28, 0x03, 0x03, // server hello
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
}, cases{
    struct TestCase{
        payload: &'static[u8],
        pkt: Option<TlsPacket>,
    }
}[
    case(empty_payload, TestCase{
        payload: EMPTY_PAYLOAD,
        pkt: None
    }),
    case(invalid_payload, TestCase{
        payload: INVALID_PAYLOAD,
        pkt: None,
    }),
    case(not_tls_payload, TestCase{
        payload: NOT_TLS_PAYLOAD,
        pkt: None,
    }),
    case(other_tls_payload, TestCase{
        payload: OTHER_TLS_PAYLOAD,
        pkt: Some(TlsPacket::Other),
    }),
    case(invalid_tls_handshake_payload, TestCase{
        payload: INVALID_HANDSHAKE_TLS_PAYLOAD,
        pkt: None,
    }),
    case(other_tls_handshake_payload, TestCase{
        payload: OTHER_HANDSHAKE_TLS_PAYLOAD,
        pkt: Some(TlsPacket::Other),
    }),
    case(client_handshake_tls_payload, TestCase{
        payload: CLIENT_HANDSHAKE_TLS_PAYLOAD,
        pkt: Some(TlsPacket::ClientHandshake(Vec::default())),
    }),
    case(server_handshake_tls_payload, TestCase{
        payload: SERVER_HANDSHAKE_TLS_PAYLOAD,
        pkt: Some(TlsPacket::ServerHandshake),
    })
] => |tc: TestCase| {
    let pkt = parse(tc.payload);
    assert_eq!(tc.pkt, pkt);
});

test_cases!(parse_tls_handshake => vars{
    const EMPTY_PAYLOAD: &[u8] = &[];
    const INVALID_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[0xff, 0x01, 0x00, 0x01, 0x00];
    const OTHER_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[0x00, 0x00, 0x00, 0x00];
    const CLIENT_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[
        0x01, 0x00, 0x00, 0x28, 0x03, 0x03, // client hello
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    const INVALID_CLIENT_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[0x01, 0x00, 0x00, 0x28, 0x03, 0x03];
    const SERVER_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[
        0x02, 0x00, 0x00, 0x28, 0x03, 0x03, // server hello
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    const INVALID_SERVER_HANDSHAKE_TLS_PAYLOAD: &[u8] = &[0x02, 0x00, 0x00, 0x28, 0x03, 0x03];
}, cases{
    struct TestCase{
        payload: &'static[u8],
        pkt: Option<TlsPacket>,
    }
}[
    case(empty_payload, TestCase{
        payload: EMPTY_PAYLOAD,
        pkt: None,
    }),
    case(invalid_handshake_tls_payload, TestCase{
        payload: INVALID_HANDSHAKE_TLS_PAYLOAD,
        pkt: None,
    }),
    case(other_handshake_tls_payload, TestCase{
        payload: OTHER_HANDSHAKE_TLS_PAYLOAD,
        pkt: Some(TlsPacket::Other),
    }),
    case(client_handshake_tls_payload, TestCase{
        payload: CLIENT_HANDSHAKE_TLS_PAYLOAD,
        pkt: Some(TlsPacket::ClientHandshake(Vec::default())),
    }),
    case(invalid_client_handshake_tls_payload, TestCase{
        payload: INVALID_CLIENT_HANDSHAKE_TLS_PAYLOAD,
        pkt: None,
    }),
    case(server_handshake_tls_payload, TestCase{
        payload: SERVER_HANDSHAKE_TLS_PAYLOAD,
        pkt: Some(TlsPacket::ServerHandshake),
    }),
    case(invalid_server_handshake_tls_payload, TestCase{
        payload: INVALID_SERVER_HANDSHAKE_TLS_PAYLOAD,
        pkt: None,
    })
] => |tc: TestCase| {
    let pkt = parse_tls_handshake(tc.payload);
    assert_eq!(tc.pkt, pkt);
});

test_cases!(parse_client_hello => vars{
    const EMPTY_EXTS: &[u8] = &[];
    const INVALID_EXTS: &[u8] = &[0x00];
    const EXTS_WITHOUT_SNI: &[u8] = &[
        0x00, 0x17, 0x00, 0x00, // extended_master_secret
        0xff, 0x01, 0x00, 0x01, 0x00 // renegotiation_info
    ];
    const EXTS_WITH_SNI: &[u8] = &[
        0x00, 0x17, 0x00, 0x00, // extended_master_secret
        0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info
        0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00,
        0x0e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x68,
        0x61, 0x63, 0x6b, 0x2e, 0x6f, 0x72, 0x67 // server_name cryptohack.org
    ];
    const EXTS_WITH_MULTIPLE_SNI: &[u8] = &[
        0x00, 0x17, 0x00, 0x00, // extended_master_secret
        0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info
        0x00, 0x00, 0x00, 0x29, 0x00, 0x27,                     // server_name
        0x00, 0x00, 0x0e, 0x63, 0x72, 0x79, 0x70, 0x74,
        0x6f, 0x68, 0x61, 0x63, 0x6b, 0x2e, 0x6f, 0x72, 0x67,   // cryptohack.org
        0x00, 0x00, 0x0e, 0x63, 0x72, 0x79, 0x70, 0x74,
        0x6f, 0x68, 0x61, 0x63, 0x6b, 0x2e, 0x63, 0x6f, 0x6d,   // cryptohack.com
        0x00, 0x00, 0x02, 0xC0, 0xaf,                           // bad sni
    ];


    const SERVER_NAME: &str = "cryptohack.org";
    const SERVER_NAME_ALT: &str = "cryptohack.com";
}, cases{
    struct TestCase{
        payload: Option<&'static[u8]>,
        pkt: TlsPacket,
    }
}[
    case(without_exts, TestCase{
        payload: None,
        pkt: TlsPacket::ClientHandshake(Vec::default())
    }),
    case(with_empty_exts, TestCase{
        payload: Some(EMPTY_EXTS),
        pkt: TlsPacket::ClientHandshake(Vec::default())
    }),
    case(with_invalid_ext, TestCase{
        payload: Some(INVALID_EXTS),
        pkt: TlsPacket::ClientHandshake(Vec::default())
    }),
    case(with_exts_without_sni, TestCase{
        payload: Some(EXTS_WITHOUT_SNI),
        pkt: TlsPacket::ClientHandshake(Vec::default())
    }),
    case(with_exts_with_sni, TestCase{
        payload: Some(EXTS_WITH_SNI),
        pkt: TlsPacket::ClientHandshake(vec![SERVER_NAME.to_string()])
    }),
    case(with_exts_with_multiple_sni, TestCase{
        payload: Some(EXTS_WITH_MULTIPLE_SNI),
        pkt: TlsPacket::ClientHandshake(vec![
            SERVER_NAME.to_string(),
            SERVER_NAME_ALT.to_string(),
        ])
    })
] => |tc: TestCase| {
    let pkt = parse_client_hello(TlsClientHelloContents{
        version: Default::default(),
        random: &[],
        session_id: None,
        ciphers: vec![],
        comp: vec![],
        ext: tc.payload,
    });

    assert_eq!(tc.pkt, pkt)
});
