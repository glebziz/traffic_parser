use crate::config;
use crate::connection::{ConnKey, Connection};
use crate::errors::Error;
use crate::nft::{IpSet, Table};
use crate::packet::{IpPacket, IpPayload, Packet, TcpPacket, TcpPayload, TlsPacket};
use crate::processor::PacketProcessor;
use log::{debug, error};
use mockall::automock;
use rtest::test_cases;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[automock]
pub trait ConnTrack {
    fn is_tracked(&self, key: ConnKey) -> bool;
    fn track_conn(&self, key: ConnKey, conn: Connection) -> Connection;
    fn untrack_conn(&self, key: ConnKey);
    fn clean_conns(&self, conn_ttl: Duration);
}

#[automock]
pub trait IpSetAdder {
    fn add_ip(&self, table: &Table, ipset: &IpSet, ip: &IpAddr) -> Result<(), Error>;
}

pub struct Detector<'a, IPAT, CTT, F>
where
    IPAT: IpSetAdder,
    CTT: ConnTrack,
    F: Fn(&IpAddr) -> bool,
{
    cfg: config::Detector,

    conn_track: Arc<CTT>,
    ip_adder: &'a IPAT,
    is_local: F,
    table: &'a Table,
    v4: &'a IpSet,
    v6: &'a IpSet,
}

impl<'a, IPAT, CTT, F> Detector<'a, IPAT, CTT, F>
where
    IPAT: IpSetAdder,
    CTT: ConnTrack,
    F: Fn(&IpAddr) -> bool,
{
    pub fn new(
        cfg: config::Detector,
        ip_adder: &'a IPAT,
        conn_track: Arc<CTT>,
        is_local: F,
        table: &'a Table,
        v4: &'a IpSet,
        v6: &'a IpSet,
    ) -> Detector<'a, IPAT, CTT, F> {
        Detector {
            cfg,
            conn_track,
            ip_adder,
            is_local,
            table,
            v4,
            v6,
        }
    }

    fn process_ip(&self, ip_pkt: &IpPacket) {
        if let IpPayload::Tcp(tcp_pkt) = &ip_pkt.payload {
            self.process_tcp(ip_pkt, tcp_pkt)
        }
    }

    fn process_tcp(&self, ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) {
        match &tcp_pkt.payload {
            TcpPayload::Tls(tls_pkt) => self.process_tls(ip_pkt, tcp_pkt, tls_pkt),
            _ => {
                if !self.conn_track.is_tracked(self.conn_key(ip_pkt, tcp_pkt)) {
                    return;
                }

                if tcp_pkt.flags.is_fin() || tcp_pkt.flags.is_rst() {
                    if tcp_pkt.flags.is_rst() && (self.is_local)(&ip_pkt.dst) {
                        self.add_ip(&ip_pkt.src);
                    }

                    self.conn_track.untrack_conn(self.conn_key(ip_pkt, tcp_pkt));
                }
            }
        };
    }

    fn process_tls(&self, ip_pkt: &IpPacket, tcp_pkt: &TcpPacket, tls_pkt: &TlsPacket) {
        match tls_pkt {
            TlsPacket::ClientHandshake(names) => {
                let conn = self.conn_track.track_conn(
                    self.conn_key(ip_pkt, tcp_pkt),
                    Connection::new(tcp_pkt.seq_num, names.to_vec()),
                );

                if conn.get_retry_count() > self.cfg.detector_count {
                    self.add_ip(&ip_pkt.dst);
                }
            }
            TlsPacket::ServerHandshake => {
                self.conn_track.untrack_conn(self.conn_key(ip_pkt, tcp_pkt));
            }
            _ => (),
        }
    }

    fn add_ip(&self, ip: &IpAddr) {
        let set = match ip {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        };

        match self.ip_adder.add_ip(self.table, set, ip) {
            Ok(_) => {
                debug!("Add IP: {ip:?}");
            }
            Err(e) => {
                error!("Add IP error: {e:?}");
            }
        };
    }

    fn conn_key(&self, ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) -> ConnKey {
        if (self.is_local)(&ip_pkt.src) {
            ConnKey {
                dst_addr: ip_pkt.dst,
                src_port: tcp_pkt.src_port,
                dst_port: tcp_pkt.dst_port,
            }
        } else {
            ConnKey {
                dst_addr: ip_pkt.src,
                src_port: tcp_pkt.dst_port,
                dst_port: tcp_pkt.src_port,
            }
        }
    }
}

impl<'a, IPAT, CTT, F> PacketProcessor for Detector<'a, IPAT, CTT, F>
where
    IPAT: IpSetAdder,
    CTT: ConnTrack,
    F: Fn(&IpAddr) -> bool,
{
    fn process(&self, packet: &Packet) {
        match packet {
            Packet::Ip(ip_pkt) => self.process_ip(ip_pkt),
        };

        self.conn_track.clean_conns(self.cfg.conn_ttl);
    }
}

test_cases!(process_ip => vars{
    use crate::nft::TABLE_FAMILY_INET;
    use std::net::Ipv4Addr;
    use crate::packet::TcpFlags;
}, cases{
    struct TestCase{
        conn_track: MockConnTrack,
        payload: IpPayload,
    }
}[
    case(other, TestCase{
        conn_track: MockConnTrack::new(),
        payload: IpPayload::Other(vec![]),
    }),
    case(tcp, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_is_tracked()
                .once()
                .returning(|_| true);

            conn_track
        },
        payload: IpPayload::Tcp(TcpPacket {
            src_port: 1,
            dst_port: 1,
            flags: TcpFlags::from(0),
            seq_num: 1,
            payload: TcpPayload::Other(vec![]),
        })
    })
] => |tc: TestCase| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());
    let ip_adder = MockIpSetAdder::new();

    let d = Detector::new(
        config::Detector::default(),
        &ip_adder,
        Arc::new(tc.conn_track),
        |_| true,
        &table,
        &ipset,
        &ipset_v6,
    );

    d.process_ip(&IpPacket{
        src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        dst: IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)),
        payload: tc.payload,
    });
});

test_cases!(process_tcp => vars{
    use crate::nft::TABLE_FAMILY_INET;
    use std::net::Ipv4Addr;
    use pnet::packet::tcp;
    use crate::packet::TcpFlags;

    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1));
    const SRC_PORT: u16 = 1234;
    const DST_PORT: u16 = 5678;
}, cases{
    struct TestCase{
        conn_track: MockConnTrack,
        ip_adder: MockIpSetAdder,
        flags: TcpFlags,
        payload: TcpPayload,
    }
}[
    case(tls, TestCase{
        conn_track: MockConnTrack::new(),
        ip_adder: MockIpSetAdder::new(),
        flags: TcpFlags::from(0),
        payload: TcpPayload::Tls(TlsPacket::Other),
    }),
    case(tcp_untracked, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_is_tracked()
                .once()
                .returning(|conn_key| {
                    assert_eq!(ConnKey {
                        dst_addr: DST_ADDR,
                        src_port: SRC_PORT,
                        dst_port: DST_PORT,
                    }, conn_key);

                    false
                });

            conn_track
        },
        ip_adder: MockIpSetAdder::new(),
        flags: TcpFlags::from(0),
        payload: TcpPayload::Other(vec![]),
    }),
    case(tcp_rst, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_is_tracked()
                .once()
                .returning(|_| true);

            conn_track.expect_untrack_conn()
                .once()
                .returning(|conn_key| {
                    assert_eq!(ConnKey {
                        dst_addr: DST_ADDR,
                        src_port: SRC_PORT,
                        dst_port: DST_PORT,
                    }, conn_key);
                });

            conn_track
        },
        ip_adder: {
            let mut ip_adder = MockIpSetAdder::new();
            ip_adder.expect_add_ip()
                .once()
                .returning(|_, _, _| Ok(()));

            ip_adder
        },
        flags: TcpFlags::from(tcp::TcpFlags::RST),
        payload: TcpPayload::Other(vec![]),
    }),
    case(tcp_fin, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_is_tracked()
                .once()
                .returning(|_| true);

            conn_track.expect_untrack_conn()
                .once()
                .returning(|_| ());

            conn_track
        },
        ip_adder: MockIpSetAdder::new(),
        flags: TcpFlags::from(tcp::TcpFlags::FIN),
        payload: TcpPayload::Other(vec![]),
    }),
] => |tc: TestCase| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());

    let d = Detector::new(
        config::Detector::default(),
        &tc.ip_adder,
        Arc::new(tc.conn_track),
        |_| true,
        &table,
        &ipset,
        &ipset_v6,
    );

    d.process_tcp(&IpPacket{
        src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        dst: DST_ADDR,
        payload: IpPayload::Other(vec![])
    }, &TcpPacket {
        src_port: SRC_PORT,
        dst_port: DST_PORT,
        flags: tc.flags,
        seq_num: 12345,
        payload: tc.payload,
    });
});

test_cases!(process_tls => vars{
    use crate::nft::TABLE_FAMILY_INET;
    use std::net::Ipv4Addr;
    use crate::packet::TcpFlags;

    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1));
    const SRC_PORT: u16 = 1234;
    const DST_PORT: u16 = 5678;
    const SEQ_NUM: u32 = 12345678;
    const SERVER_NAME: &str = "example.com";
}, cases{
    struct TestCase{
        conn_track: MockConnTrack,
        ip_adder: MockIpSetAdder,
        tls_pkt: TlsPacket,
    }
}[
    case(other_tls, TestCase{
        conn_track: MockConnTrack::new(),
        ip_adder: MockIpSetAdder::new(),
        tls_pkt: TlsPacket::Other,
    }),
    case(new_client_hello, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_track_conn()
                .once()
                .returning(|conn_key, conn| {
                    assert_eq!(ConnKey {
                        dst_addr: DST_ADDR,
                        src_port: SRC_PORT,
                        dst_port: DST_PORT,
                    }, conn_key);
                    assert_eq!(Connection::new(SEQ_NUM, vec![SERVER_NAME.to_string()]), conn);

                    conn
                });

            conn_track
        },
        ip_adder: MockIpSetAdder::new(),
        tls_pkt: TlsPacket::ClientHandshake(vec![SERVER_NAME.to_string()]),
    }),
    case(existing_client_hello, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_track_conn()
                .once()
                .returning(|_, _| {
                    let mut conn = Connection::new(SEQ_NUM, vec![SERVER_NAME.to_string()]);
                    conn.inc_retry_count();

                    conn
                });

            conn_track
        },
        ip_adder: {
            let mut adder = MockIpSetAdder::new();
            adder.expect_add_ip()
                .once()
                .returning(|_, _, _| Ok(()));

            adder
        },
        tls_pkt: TlsPacket::ClientHandshake(vec![SERVER_NAME.to_string()]),
    }),
    case(server_hello, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_untrack_conn()
                .once()
                .returning(|conn_key| {
                    assert_eq!(ConnKey {
                        dst_addr: DST_ADDR,
                        src_port: SRC_PORT,
                        dst_port: DST_PORT,
                    }, conn_key);
                });

            conn_track
        },
        ip_adder: MockIpSetAdder::new(),
        tls_pkt: TlsPacket::ServerHandshake,
    }),
] => |tc: TestCase| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());

    let d = Detector::new(
        config::Detector{
            detector_count: 0,
            ..config::Detector::default()
        },
        &tc.ip_adder,
        Arc::new(tc.conn_track),
        |_| true,
        &table,
        &ipset,
        &ipset_v6,
    );

    d.process_tls(&IpPacket{
        src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        dst: DST_ADDR,
        payload: IpPayload::Other(vec![])
    }, &TcpPacket {
        src_port: SRC_PORT,
        dst_port: DST_PORT,
        flags: TcpFlags::from(0),
        seq_num: SEQ_NUM,
        payload: TcpPayload::Other(vec![]),
    }, &tc.tls_pkt);
});

test_cases!(add_ip => vars{
    use std::net::{Ipv4Addr, Ipv6Addr};
    use crate::nft::TABLE_FAMILY_INET;
    use crate::nft::TableFamily;

    const TABLE_FAMILY: TableFamily = TABLE_FAMILY_INET;
    const TABLE: &str = "table";
    const IPSET: &str = "ipset";
    const IPSET_V6: &str = "ipset_v6";

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const IP_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8));
}, cases{
    struct TestCase{
        ip_adder: MockIpSetAdder,
        ip: IpAddr,
    }
}[
    case(ipv4, TestCase{
        ip_adder: {
            let mut adder = MockIpSetAdder::new();
            adder.expect_add_ip()
                .once()
                .returning(|table, set, ip| {
                    assert_eq!(Table::new(TABLE.to_string(), TABLE_FAMILY), *table);
                    assert_eq!(IpSet::new(IPSET.to_string()), *set);
                    assert_eq!(IP, *ip);

                    Ok(())
                });

            adder
        },
        ip: IP,
    }),
    case(ipv6, TestCase{
        ip_adder: {
            let mut adder = MockIpSetAdder::new();
            adder.expect_add_ip()
                .once()
                .returning(|table, set, ip| {
                    assert_eq!(Table::new(TABLE.to_string(), TABLE_FAMILY), *table);
                    assert_eq!(IpSet::new(IPSET_V6.to_string()), *set);
                    assert_eq!(IP_V6, *ip);

                    Ok(())
                });

            adder
        },
        ip: IP_V6,
    }),
    case(error, TestCase{
        ip_adder: {
            let mut adder = MockIpSetAdder::new();
            adder.expect_add_ip()
                .once()
                .returning(|_, _, _| Err(Error::External("Some error".to_string())));

            adder
        },
        ip: IP,
    })
] => |tc: TestCase| {
    let table = Table::new(TABLE.to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new(IPSET.to_string());
    let ipset_v6 = IpSet::new(IPSET_V6.to_string());

    let d = Detector::new(
        config::Detector::default(),
        &tc.ip_adder,
        Arc::new(MockConnTrack::new()),
        |_| true,
        &table,
        &ipset,
        &ipset_v6,
    );

    d.add_ip(&tc.ip);
});

test_cases!(conn_key => vars{
    use std::net::Ipv4Addr;
    use crate::nft::TABLE_FAMILY_INET;
    use crate::packet::TcpFlags;

    const SRC_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1));
    const SRC_PORT: u16 = 1234;
    const DST_PORT: u16 = 5678;
    const SEQ_NUM: u32 = 12345678;
}, cases{
    struct TestCase{
        is_local: fn(&IpAddr) -> bool,
        conn_key: ConnKey,
    }
}[
    case(src_pkt, TestCase{
        is_local: |_| {
            true
        },
        conn_key: ConnKey {
            dst_addr: DST_ADDR,
            src_port: SRC_PORT,
            dst_port: DST_PORT,
        }
    }),
    case(dst_pkt, TestCase{
        is_local: |_| {
            false
        },
        conn_key: ConnKey {
            dst_addr: SRC_ADDR,
            src_port: DST_PORT,
            dst_port: SRC_PORT,
        }
    })
] => |tc: TestCase| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());
    let ip_adder = MockIpSetAdder::new();

    let d = Detector::new(
        config::Detector::default(),
        &ip_adder,
        Arc::new(MockConnTrack::new()),
        tc.is_local,
        &table,
        &ipset,
        &ipset_v6,
    );

    let conn_key = d.conn_key(&IpPacket{
        src: SRC_ADDR,
        dst: DST_ADDR,
        payload: IpPayload::Other(vec![]),
    }, &TcpPacket{
        src_port: SRC_PORT,
        dst_port: DST_PORT,
        flags: TcpFlags::from(0),
        seq_num: SEQ_NUM,
        payload: TcpPayload::Other(vec![]),
    });

    assert_eq!(tc.conn_key, conn_key);
});

test_cases!(process => vars{
    use mockall::predicate;
    use std::net::Ipv4Addr;
    use crate::nft::TABLE_FAMILY_INET;

    const TTL: Duration = Duration::from_secs(10);
}, cases{
    struct TestCase{
        conn_track: MockConnTrack,
    }
}[
    case(sucess, TestCase{
        conn_track: {
            let mut conn_track = MockConnTrack::new();
            conn_track.expect_clean_conns()
                .with(predicate::eq(TTL))
                .once()
                .return_const(());

            conn_track
        }
    })
] => |tc: TestCase| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());
    let ip_adder = MockIpSetAdder::new();

    let d = Detector::new(
        config::Detector{
            conn_ttl: TTL,
            ..config::Detector::default()
        },
        &ip_adder,
        Arc::new(tc.conn_track),
        |_| true,
        &table,
        &ipset,
        &ipset_v6,
    );

    d.process(&Packet::Ip(IpPacket{
        src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        dst: IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)),
        payload: IpPayload::Other(vec![]),
    }))
});
