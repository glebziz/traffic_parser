use rtest::test_cases;
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InterfaceNotFound(String, Vec<(String, Option<String>)>),
    PermissionDenied,
    NotFound,
    UnsupportedTableFamily(String),
    TableNotFound(String),
    IpSetNotFound(String),
    External(String),
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::InterfaceNotFound(name, allowed) => match allowed.len() {
                    0 => "No interfaces found".to_string(),
                    _ => {
                        format!(
                            "Interface {} not found\nAllowed interfaces:\n\t{}",
                            name,
                            allowed
                                .iter()
                                .map(|(n, desc)| match desc {
                                    Some(desc) => format!("{n} ({desc})"),
                                    None => n.to_string(),
                                })
                                .collect::<Vec<_>>()
                                .join("\n\t")
                        )
                    }
                },
                Error::PermissionDenied => "Permission denied".to_string(),
                Error::NotFound => "Not found".to_string(),
                Error::UnsupportedTableFamily(family) =>
                    format!("Unsupported table family {family}"),
                Error::TableNotFound(name) => format!("Table {name} not found"),
                Error::IpSetNotFound(name) => format!("IpSet {name} not found"),
                Error::External(e) => format!("External error: {e}"),
            }
        )
    }
}

test_cases!(errors => vars{
    const IFACE1: &str = "eth0";
    const IFACE2: &str = "eth1";
    const IFACE3: &str = "eth2";
    const IFACE_DESCRIPTION: &str = "eth description";

    const TABLE_FAMILY: &str = "inet";
    const TABLE: &str = "filter";
    const IPSET: &str = "ipset";
    const EXTERNAL_MESSAGE: &str = "external message";
}, cases{
    struct TestCase{
        err: Error,
        str: String,
    }
}[
    case(interface_not_found_without_allowed, TestCase{
        err: Error::InterfaceNotFound(IFACE1.to_string(), vec![]),
        str: "No interfaces found".to_string(),
    }),
    case(interface_not_found, TestCase{
        err: Error::InterfaceNotFound(IFACE1.to_string(), vec![
            (IFACE2.to_string(), Some(IFACE_DESCRIPTION.to_string())),
            (IFACE3.to_string(), None),
        ]),
        str: "Interface eth0 not found
Allowed interfaces:
\teth1 (eth description)
\teth2".to_string(),
    }),
    case(permission_denied, TestCase{
        err: Error::PermissionDenied,
        str: "Permission denied".to_string(),
    }),
    case(not_found, TestCase{
        err: Error::NotFound,
        str: "Not found".to_string(),
    }),
    case(unsupported_table_family, TestCase{
        err: Error::UnsupportedTableFamily(TABLE_FAMILY.to_string()),
        str: "Unsupported table family inet".to_string(),
    }),
    case(table_not_found, TestCase{
        err: Error::TableNotFound(TABLE.to_string()),
        str: "Table filter not found".to_string(),
    }),
    case(ip_set_not_found, TestCase{
        err: Error::IpSetNotFound(IPSET.to_string()),
        str: "IpSet ipset not found".to_string(),
    }),
    case(external, TestCase{
        err: Error::External(EXTERNAL_MESSAGE.to_string()),
        str: "External error: external message".to_string(),
    })
] => |tc: TestCase| {
    let str = tc.err.to_string();
    assert_eq!(tc.str, str);
});
