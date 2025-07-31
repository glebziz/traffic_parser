use crate::errors::Error;
use log::info;
use pcap::{Active, Capture, Device};
use rtest::test_cases;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time;

const DEFAULT_PKT_SIZE: i32 = 4096;

pub struct Interface {
    filter: Option<String>,
    timeout: Option<time::Duration>,
    pkt_size: i32,

    dev: Device,
    addresses: HashSet<IpAddr>,
}

impl Interface {
    pub fn find(iface_name: String) -> Result<Interface, Error> {
        let devs = match Device::list() {
            Ok(devs) => devs,
            Err(e) => return Err(Error::External(e.to_string())),
        };

        let dev = match devs.iter().find(|d| d.name == iface_name) {
            Some(dev) => dev,
            None => {
                return Err(Error::InterfaceNotFound(
                    iface_name.to_string(),
                    devs.iter()
                        .map(|d| (d.name.clone(), d.desc.clone()))
                        .collect::<Vec<_>>(),
                ));
            }
        };

        let iface = Interface {
            filter: None,
            timeout: None,
            pkt_size: DEFAULT_PKT_SIZE,

            dev: dev.clone(),
            addresses: dev.addresses.iter().map(|addr| addr.addr).collect(),
        };

        Ok(iface)
    }
}

impl Interface {
    pub fn set_filter(mut self, filter: String) -> Interface {
        self.filter = Some(filter);
        self
    }

    pub fn set_timeout(mut self, timeout: time::Duration) -> Interface {
        self.timeout = Some(timeout);
        self
    }

    pub fn set_pkt_size(mut self, size: i32) -> Interface {
        self.pkt_size = size;
        self
    }

    pub fn is_local(&self, addr: &IpAddr) -> bool {
        self.addresses.contains(addr)
    }

    pub fn open(&self) -> Result<Capture<Active>, Error> {
        let cap = match Capture::from_device(self.dev.clone()) {
            Ok(cap) => cap,
            Err(e) => return Err(Error::External(e.to_string())),
        };

        let cap = match self.timeout {
            Some(timeout) => cap.timeout(timeout.as_millis() as i32),
            _ => cap,
        };

        let mut cap = match cap.promisc(false).snaplen(self.pkt_size).open() {
            Ok(cap) => cap,
            Err(e) => return Err(Error::External(e.to_string())),
        };

        if let Some(filter) = &self.filter {
            if let Err(e) = cap.filter(filter, true) {
                return Err(Error::External(e.to_string()));
            }
        }

        info!("Start capturing on {}", self.dev.name);
        Ok(cap)
    }

    #[cfg(test)]
    fn default() -> Interface {
        Interface {
            filter: None,
            timeout: None,
            pkt_size: 0,
            dev: Device {
                name: "".to_string(),
                desc: None,
                addresses: vec![],
                flags: pcap::DeviceFlags {
                    if_flags: pcap::IfFlags::empty(),
                    connection_status: pcap::ConnectionStatus::Unknown,
                },
            },
            addresses: HashSet::default(),
        }
    }
}

test_cases!(set_filter => vars{
    const FILTER: &str = "test_filter";
    const FILTER_OLD: &str = "old_filter";
}, cases{
    struct TestCase {
        iface: Interface,
        filter: &'static str
    }
}[
    case(with_empty_filter, TestCase {
        iface: Interface::default(),
        filter: FILTER,
    }),
    case(with_existing_filter, TestCase {
        iface: Interface {
            filter: Some(FILTER_OLD.to_string()),
            ..Interface::default()
        },
        filter: FILTER,
    }),
] => |tc: TestCase|{
    let iface = tc.iface.set_filter(tc.filter.to_string());
    assert_eq!(tc.filter, iface.filter.unwrap().as_str());
});

test_cases!(set_timeout => vars{
    const TIMEOUT: time::Duration = time::Duration::from_secs(1);
    const TIMEOUT_OLD: time::Duration = time::Duration::from_secs(10);
}, cases{
    struct TestCase {
        iface: Interface,
        timeout: time::Duration
    }
}[
    case(with_empty_timeout, TestCase {
        iface: Interface::default(),
        timeout: TIMEOUT,
    }),
    case(with_existing_filter, TestCase {
        iface: Interface {
            timeout: Some(TIMEOUT_OLD),
            ..Interface::default()
        },
        timeout: TIMEOUT,
    }),
] => |tc: TestCase|{
    let iface = tc.iface.set_timeout(tc.timeout);
    assert_eq!(tc.timeout, iface.timeout.unwrap());
});

test_cases!(set_pkt_size => vars{
    const PKT_SIZE: i32 = 100;
    const PKT_SIZE_OLD: i32 = 10;
}, cases{
    struct TestCase {
        iface: Interface,
        pkt_size: i32
    }
}[
    case(with_zero_pkt_size, TestCase {
        iface: Interface::default(),
        pkt_size: PKT_SIZE,
    }),
    case(with_existing_pkt_size, TestCase {
        iface: Interface {
            pkt_size: PKT_SIZE_OLD,
            ..Interface::default()
        },
        pkt_size: PKT_SIZE
    })
] => |tc: TestCase| {
    let iface = tc.iface.set_pkt_size(tc.pkt_size);
    assert_eq!(tc.pkt_size, iface.pkt_size);
});

test_cases!(is_local => vars{
    use std::net::Ipv4Addr;

    const IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    const IP_OTHER_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
}, cases{
    struct TestCase {
        iface: Interface,
        is_local: bool
    }
}[
    case(with_empty_addresses, TestCase{
        iface: Interface::default(),
        is_local: false,
    }), case(with_local_not_empty_addresses, TestCase{
        iface: Interface {
            addresses: HashSet::from([IP_ADDR]),
            ..Interface::default()
        },
        is_local: true,
    }), case(without_local_not_empty_addresses, TestCase{
        iface: Interface {
            addresses: HashSet::from([IP_OTHER_ADDR]),
            ..Interface::default()
        },
        is_local: false,
    })
] => |tc: TestCase| {
    assert_eq!(tc.is_local, tc.iface.is_local(&IP_ADDR));
});
