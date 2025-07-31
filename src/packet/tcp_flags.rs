use pnet::packet::tcp;
use rtest::test_cases;

#[derive(Debug, PartialEq)]
pub struct TcpFlags(u8);

impl From<u8> for TcpFlags {
    fn from(flags: u8) -> Self {
        TcpFlags(flags)
    }
}

impl TcpFlags {
    fn is_set(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    pub fn is_cwr(&self) -> bool {
        self.is_set(tcp::TcpFlags::CWR)
    }

    pub fn is_ece(&self) -> bool {
        self.is_set(tcp::TcpFlags::ECE)
    }

    pub fn is_urg(&self) -> bool {
        self.is_set(tcp::TcpFlags::URG)
    }

    pub fn is_ack(&self) -> bool {
        self.is_set(tcp::TcpFlags::ACK)
    }

    pub fn is_psh(&self) -> bool {
        self.is_set(tcp::TcpFlags::PSH)
    }
    pub fn is_rst(&self) -> bool {
        self.is_set(tcp::TcpFlags::RST)
    }

    pub fn is_syn(&self) -> bool {
        self.is_set(tcp::TcpFlags::SYN)
    }

    pub fn is_fin(&self) -> bool {
        self.is_set(tcp::TcpFlags::FIN)
    }
}

test_cases!(is_cwr => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_cwr, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: false,
    }),
    case(flags_is_cwr, TestCase{
        flags: tcp::TcpFlags::CWR,
        is_set: true,
    }),
    case(flags_with_cwr, TestCase{
        flags: tcp::TcpFlags::CWR | tcp::TcpFlags::FIN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_cwr();
    assert_eq!(tc.is_set, is_set);
});

test_cases!(is_ece => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_ece, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: false,
    }),
    case(flags_is_ece, TestCase{
        flags: tcp::TcpFlags::ECE,
        is_set: true,
    }),
    case(flags_with_ece, TestCase{
        flags: tcp::TcpFlags::ECE | tcp::TcpFlags::FIN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_ece();
    assert_eq!(tc.is_set, is_set);
});

test_cases!(is_urg => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_urg, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: false,
    }),
    case(flags_is_urg, TestCase{
        flags: tcp::TcpFlags::URG,
        is_set: true,
    }),
    case(flags_with_urg, TestCase{
        flags: tcp::TcpFlags::URG | tcp::TcpFlags::FIN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_urg();
    assert_eq!(tc.is_set, is_set);
});

test_cases!(is_ack => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_ack, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: false,
    }),
    case(flags_is_ack, TestCase{
        flags: tcp::TcpFlags::ACK,
        is_set: true,
    }),
    case(flags_with_ack, TestCase{
        flags: tcp::TcpFlags::ACK | tcp::TcpFlags::FIN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_ack();
    assert_eq!(tc.is_set, is_set);
});

test_cases!(is_psh => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_psh, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: false,
    }),
    case(flags_is_psh, TestCase{
        flags: tcp::TcpFlags::PSH,
        is_set: true,
    }),
    case(flags_with_psh, TestCase{
        flags: tcp::TcpFlags::PSH | tcp::TcpFlags::FIN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_psh();
    assert_eq!(tc.is_set, is_set);
});

test_cases!(is_rst => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_rst, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: false,
    }),
    case(flags_is_rst, TestCase{
        flags: tcp::TcpFlags::RST,
        is_set: true,
    }),
    case(flags_with_rst, TestCase{
        flags: tcp::TcpFlags::RST | tcp::TcpFlags::FIN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_rst();
    assert_eq!(tc.is_set, is_set);
});

test_cases!(is_syn => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_syn, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: false,
    }),
    case(flags_is_syn, TestCase{
        flags: tcp::TcpFlags::SYN,
        is_set: true,
    }),
    case(flags_with_syn, TestCase{
        flags: tcp::TcpFlags::SYN | tcp::TcpFlags::FIN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_syn();
    assert_eq!(tc.is_set, is_set);
});

test_cases!(is_fin => vars{}, cases{
    struct TestCase{
        flags: u8,
        is_set: bool,
    }
}[
    case(zero_flags, TestCase{
        flags: 0,
        is_set: false,
    }),
    case(flags_without_fin, TestCase{
        flags: tcp::TcpFlags::SYN,
        is_set: false,
    }),
    case(flags_is_fin, TestCase{
        flags: tcp::TcpFlags::FIN,
        is_set: true,
    }),
    case(flags_with_fin, TestCase{
        flags: tcp::TcpFlags::FIN | tcp::TcpFlags::SYN,
        is_set: true,
    })
] => |tc: TestCase| {
    let is_set = TcpFlags::from(tc.flags).is_fin();
    assert_eq!(tc.is_set, is_set);
});
