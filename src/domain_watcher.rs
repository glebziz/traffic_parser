use crate::errors::Error;
use crate::nft::{IpSet, Table};
use crate::packet::{IpPacket, IpPayload, Packet, TcpPacket, TcpPayload, TlsPacket};
use crate::processor::PacketProcessor;
use log::{debug, error};
use mockall::automock;
use rtest::test_cases;
use std::net::IpAddr;

#[automock]
pub trait IpSetAdder {
    fn add_ip(&self, table: &Table, ipset: &IpSet, ip: &IpAddr) -> Result<(), Error>;
}

pub struct DomainWatcher<'a, IPAT>
where
    IPAT: IpSetAdder,
{
    domains: Vec<String>,
    ip_adder: &'a IPAT,
    table: &'a Table,
    v4: &'a IpSet,
    v6: &'a IpSet,
}

impl<'a, IPAT> DomainWatcher<'a, IPAT>
where
    IPAT: IpSetAdder,
{
    pub fn new(
        domains: Vec<String>,
        ip_adder: &'a IPAT,
        table: &'a Table,
        v4: &'a IpSet,
        v6: &'a IpSet,
    ) -> DomainWatcher<'a, IPAT> {
        DomainWatcher {
            domains,
            ip_adder,
            table,
            v4,
            v6,
        }
    }

    fn process_ip(&self, ip_pkt: &IpPacket) {
        if let IpPayload::Tcp(tcp_pkt) = &ip_pkt.payload {
            self.process_tcp(tcp_pkt, ip_pkt.dst)
        }
    }

    fn process_tcp(&self, tcp_pkt: &TcpPacket, ip: IpAddr) {
        if let TcpPayload::Tls(tls_pkt) = &tcp_pkt.payload {
            self.process_tls(tls_pkt, ip)
        }
    }

    fn process_tls(&self, tls_pkt: &TlsPacket, ip: IpAddr) {
        if let TlsPacket::ClientHandshake(names) = tls_pkt {
            if self.domains.iter().any(|domain| {
                names
                    .iter()
                    .any(|host| host.to_lowercase().contains(&domain.to_lowercase()))
            }) {
                self.add_ip(ip);
            }
        }
    }

    fn add_ip(&self, ip: IpAddr) {
        let set = match ip {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        };

        match self.ip_adder.add_ip(self.table, set, &ip) {
            Ok(_) => {
                debug!("Add IP: {ip:?}");
            }
            Err(e) => {
                error!("Add IP error: {e:?}");
            }
        };
    }
}

impl<'a, IPAT> PacketProcessor for DomainWatcher<'a, IPAT>
where
    IPAT: IpSetAdder,
{
    fn process(&self, packet: &Packet) {
        match packet {
            Packet::Ip(ip_pkt) => self.process_ip(ip_pkt),
        };
    }
}

test_cases!(process_ip => vars{
    use crate::nft::TABLE_FAMILY_INET;
    use std::net::Ipv4Addr;
    use crate::packet::TcpFlags;
}, cases{
    struct TestCase{
        payload: IpPayload,
    }
}[
    case(other, TestCase{
        payload: IpPayload::Other(vec![]),
    }),
    case(tcp, TestCase{
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

    let dw = DomainWatcher::new(
        vec![],
        &ip_adder,
        &table,
        &ipset,
        &ipset_v6,
    );

    dw.process_ip(&IpPacket{
        src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        dst: IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)),
        payload: tc.payload,
    });
});

test_cases!(process_tcp => vars{
    use crate::nft::TABLE_FAMILY_INET;
    use std::net::Ipv4Addr;
    use crate::packet::TcpFlags;

    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1));
    const SRC_PORT: u16 = 1234;
    const DST_PORT: u16 = 5678;
}, cases{
    struct TestCase{
        payload: TcpPayload,
    }
}[
    case(tls, TestCase{
        payload: TcpPayload::Tls(TlsPacket::Other),
    }),
    case(other, TestCase{
        payload: TcpPayload::Other(vec![]),
    })
] => |tc: TestCase| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());
    let ip_adder = MockIpSetAdder::new();

    let dw = DomainWatcher::new(
        vec![],
        &ip_adder,
        &table,
        &ipset,
        &ipset_v6,
    );

    dw.process_tcp(&TcpPacket {
        src_port: SRC_PORT,
        dst_port: DST_PORT,
        flags: TcpFlags::from(0),
        seq_num: 12345,
        payload: tc.payload,
    }, DST_ADDR);
});

test_cases!(process_tls => vars{
    use crate::nft::TABLE_FAMILY_INET;
    use std::net::Ipv4Addr;

    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1));
    const SERVER_NAME1: &str = "www.example.com";
    const SERVER_NAME2: &str = "www.example.net";
    const DOMAIN: &str = "example.com";
}, cases{
    struct TestCase{
        ip_adder: MockIpSetAdder,
        tls_pkt: TlsPacket,
    }
}[
    case(other_tls, TestCase{
        ip_adder: MockIpSetAdder::new(),
        tls_pkt: TlsPacket::Other,
    }),
    case(success_client_hello, TestCase{
        ip_adder: {
            let mut ip_adder = MockIpSetAdder::new();
            ip_adder.expect_add_ip()
            .once()
            .returning(|_, _, _| {
                Ok(())
            });

            ip_adder
        },
        tls_pkt: TlsPacket::ClientHandshake(vec![SERVER_NAME1.to_string()]),
    }),
    case(client_hello, TestCase{
        ip_adder: MockIpSetAdder::new(),
        tls_pkt: TlsPacket::ClientHandshake(vec![SERVER_NAME2.to_string()]),
    }),
] => |tc: TestCase| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());

    let dw = DomainWatcher::new(
        vec![DOMAIN.to_string()],
        &tc.ip_adder,
        &table,
        &ipset,
        &ipset_v6,
    );

    dw.process_tls(&tc.tls_pkt, DST_ADDR);
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

    let dw = DomainWatcher::new(
        vec![],
        &tc.ip_adder,
        &table,
        &ipset,
        &ipset_v6,
    );

    dw.add_ip(tc.ip);
});

test_cases!(process => vars{
    use std::net::Ipv4Addr;
    use crate::nft::TABLE_FAMILY_INET;
}, cases{
    struct TestCase{}
}[
    case(sucess, TestCase{})
] => |_| {
    let table = Table::new("table".to_string(), TABLE_FAMILY_INET);
    let ipset = IpSet::new("ipset".to_string());
    let ipset_v6 = IpSet::new("ipset_v6".to_string());
    let ip_adder = MockIpSetAdder::new();

    let dw = DomainWatcher::new(
        vec![],
        &ip_adder,
        &table,
        &ipset,
        &ipset_v6,
    );

    dw.process(&Packet::Ip(IpPacket{
        src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        dst: IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)),
        payload: IpPayload::Other(vec![]),
    }))
});
