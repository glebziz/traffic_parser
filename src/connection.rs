use crate::{detector, http};
use rtest::test_cases;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Eq, Hash, PartialEq, Serialize, Clone, PartialOrd, Ord)]
pub struct ConnKey {
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Display for ConnKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, ":{}->{}:{}", self.src_port, self.dst_addr, self.dst_port)
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Connection {
    #[serde(skip_serializing)]
    track_start: Option<Instant>,
    retry_count: u8,
    seq: u32,
    names: Vec<String>,
}

impl Connection {
    pub fn new(seq: u32, names: Vec<String>) -> Self {
        Self {
            track_start: Some(Instant::now()),
            retry_count: 0,
            seq,
            names,
        }
    }

    pub fn get_retry_count(&self) -> u8 {
        self.retry_count
    }

    pub fn inc_retry_count(&mut self) {
        self.retry_count += 1;
    }
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.retry_count == other.retry_count && self.seq == other.seq && self.names == other.names
    }
}

pub struct ConnTrack {
    active: Mutex<HashMap<ConnKey, Connection>>,
}

impl ConnTrack {
    pub fn new() -> ConnTrack {
        ConnTrack {
            active: Mutex::new(Default::default()),
        }
    }
}

impl detector::ConnTrack for ConnTrack {
    fn is_tracked(&self, key: ConnKey) -> bool {
        self.active.lock().unwrap().contains_key(&key)
    }

    fn track_conn(&self, key: ConnKey, conn: Connection) -> Connection {
        let mut active = self.active.lock().unwrap();

        match active.get_mut(&key) {
            Some(c) if c.seq != conn.seq => {
                *c = conn;
                c.clone()
            }
            Some(c) if c.seq == conn.seq => {
                c.inc_retry_count();
                c.clone()
            }
            _ => {
                active.insert(key, conn.clone());
                conn
            }
        }
    }

    fn untrack_conn(&self, key: ConnKey) {
        self.active.lock().unwrap().remove(&key);
    }

    fn clean_conns(&self, conn_ttl: Duration) {
        self.active
            .lock()
            .unwrap()
            .retain(|_, conn| conn.track_start.unwrap().elapsed() < conn_ttl);
    }
}

impl http::ConnTrack for ConnTrack {
    fn get_active_conn(&self) -> HashMap<ConnKey, Connection> {
        self.active.lock().unwrap().clone()
    }
}

test_cases!(conn_key_to_string => vars{
    use std::net::{Ipv4Addr};
}, cases{
    struct TestCase{
        conn_key: ConnKey,
        str: String,
    }
}[
    case(success, TestCase{
        conn_key: ConnKey{
            dst_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            src_port: 1,
            dst_port: 2,
        },
        str: ":1->1.2.3.4:2".to_string()
    }),
] => |tc: TestCase| {
    let str = tc.conn_key.to_string();
    assert_eq!(tc.str, str);
});

test_cases!(is_tracked => vars{
    use crate::detector::ConnTrack as ConnTrackTrait;
    use std::net::{Ipv4Addr};

    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const SRC_PORT: u16 = 1;
    const DST_PORT: u16 = 2;
}, cases{
    struct TestCase{
        conn_track: ConnTrack,
        is_tracked: bool,
    }
}[
    case(tracked, TestCase{
        conn_track: ConnTrack {
            active: Mutex::new(vec![(ConnKey{
                dst_addr: DST_ADDR,
                src_port: SRC_PORT,
                dst_port: DST_PORT,
            }, Connection::new(1, vec![]))].into_iter().collect()),
        },
        is_tracked: true,
    }),
    case(not_tracked, TestCase{
        conn_track: ConnTrack::new(),
        is_tracked: false
    })
] => |tc: TestCase| {
    let is_tracked = tc.conn_track.is_tracked(ConnKey{
        dst_addr: DST_ADDR,
        src_port: SRC_PORT,
        dst_port: DST_PORT,
    });

    assert_eq!(tc.is_tracked, is_tracked);
});

test_cases!(track_conn => vars{
    use crate::detector::ConnTrack as ConnTrackTrait;
    use std::net::{Ipv4Addr};

    const CONN_KEY: ConnKey = ConnKey{
        dst_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        src_port: 1,
        dst_port: 2,
    };
    const CONN: Connection = Connection{
        track_start: None,
        retry_count: 1,
        seq: 2,
        names: vec![],
    };
}, cases{
    struct TestCase{
        conn_track: ConnTrack,
        conn: Connection,
    }
}[
    case(new_connection, TestCase{
        conn_track: ConnTrack::new(),
        conn: CONN,
    }),
    case(active_connection, TestCase{
        conn_track: ConnTrack {
            active: Mutex::new(vec![(CONN_KEY, CONN)].into_iter().collect::<HashMap<_, _>>()),
        },
        conn: Connection{
            retry_count: CONN.retry_count + 1,
            ..CONN
        },
    }),
    case(new_connection_with_active_key, TestCase{
        conn_track: ConnTrack {
            active: Mutex::new(vec![(CONN_KEY, Connection{
                seq: CONN.seq + 1,
                ..CONN
            })].into_iter().collect::<HashMap<_, _>>()),
        },
        conn: CONN,
    }),
] => |tc: TestCase| {
    let conn = tc.conn_track.track_conn(CONN_KEY, CONN);

    assert_eq!(tc.conn, conn);
    assert_eq!(Some(&tc.conn), tc.conn_track.active.lock().unwrap().get(&CONN_KEY));
});

test_cases!(untrack_conn => vars{
    use crate::detector::ConnTrack as ConnTrackTrait;
    use std::net::{Ipv4Addr};

    const CONN_KEY: ConnKey = ConnKey{
        dst_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        src_port: 1,
        dst_port: 2,
    };
    const CONN: Connection = Connection{
        track_start: None,
        retry_count: 1,
        seq: 2,
        names: vec![],
    };
}, cases{
    struct TestCase{
        conn_track: ConnTrack,
    }
}[
    case(empty, TestCase{
        conn_track: ConnTrack::new(),
    }),
    case(active_connection, TestCase{
        conn_track: ConnTrack {
            active: Mutex::new(vec![(CONN_KEY, CONN)].into_iter().collect::<HashMap<_, _>>()),
        }
    })
] => |tc: TestCase| {
    tc.conn_track.untrack_conn(CONN_KEY);
    assert!(!tc.conn_track.active.lock().unwrap().contains_key(&CONN_KEY))
});

test_cases!(clean_conns => vars{
    use crate::detector::ConnTrack as ConnTrackTrait;
    use std::net::{Ipv4Addr};
    use std::ops::{Add,Sub,Mul};

    const TTL: Duration = Duration::from_secs(1);
    const DST_ADDR1: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const DST_ADDR2: IpAddr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

    const CONN_KEY1: ConnKey = ConnKey{
        dst_addr: DST_ADDR1,
        src_port: 1,
        dst_port: 2,
    };
    const CONN_KEY2: ConnKey = ConnKey{
        dst_addr: DST_ADDR2,
        src_port: 2,
        dst_port: 3,
    };
    const CONN_KEY3: ConnKey = ConnKey{
        dst_addr: DST_ADDR2,
        src_port: 3,
        dst_port: 4,
    };
    const CONN: Connection = Connection{
        track_start: None,
        retry_count: 1,
        seq: 2,
        names: vec![],
    };
}, cases{
    struct TestCase{
        conn_track: ConnTrack,
        active_conns: Vec<ConnKey>,
    }
}[
    case(empty, TestCase{
        conn_track: ConnTrack::new(),
        active_conns: Default::default(),
    }),
    case(active_conns, TestCase{
        conn_track: ConnTrack {
            active: Mutex::new(vec![(CONN_KEY1, Connection{
                track_start: Some(Instant::now()),
                ..CONN
            }), (CONN_KEY2, Connection{
                track_start: Some(Instant::now().sub(TTL.mul(2))),
                ..CONN
            }), (CONN_KEY3, Connection{
                track_start: Some(Instant::now().sub(TTL).add(Duration::from_millis(10))),
                ..CONN
            })].into_iter().collect::<HashMap<_, _>>())
        },
        active_conns: vec![CONN_KEY1, CONN_KEY3]
    })
] => |tc: TestCase| {
    tc.conn_track.clean_conns(TTL);

    let mut conns = tc.conn_track.active.lock().unwrap().clone().into_keys().collect::<Vec<_>>();
    conns.sort();

    assert_eq!(tc.active_conns, conns);
});

test_cases!(get_active_conn => vars{
    use crate::http::ConnTrack as ConnTrackTrait;
    use std::net::{Ipv4Addr};

    const CONN_KEY: ConnKey = ConnKey{
        dst_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        src_port: 1,
        dst_port: 2,
    };
    const CONN: Connection = Connection{
        track_start: None,
        retry_count: 1,
        seq: 2,
        names: vec![],
    };
}, cases{
    struct TestCase{
        conn_track: ConnTrack,
        active_conns: HashMap<ConnKey, Connection>,
    }
}[
    case(empty, TestCase{
        conn_track: ConnTrack::new(),
        active_conns: HashMap::new(),
    }),
    case(active_conns, TestCase{
        conn_track: ConnTrack {
            active: Mutex::new(vec![(CONN_KEY, CONN)].into_iter().collect::<HashMap<_, _>>())
        },
        active_conns: vec![(CONN_KEY, CONN)].into_iter().collect::<HashMap<_, _>>(),
    })
] => |tc: TestCase| {
    let active_conns = tc.conn_track.get_active_conn();
    assert_eq!(tc.active_conns, active_conns);
});
