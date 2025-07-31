use crate::errors::Error;
use crate::nft::constants::NFTA_TABLE_NAME;
use netlink_packet_core::{NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::constants::NFNETLINK_V0;
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterMessageInner};
use netlink_packet_utils::nla::DefaultNla;
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq)]
pub struct TableFamily(pub(super) u8);

pub const TABLE_FAMILY_INET: TableFamily = TableFamily(libc::NFPROTO_INET as u8);
pub const TABLE_FAMILY_IP: TableFamily = TableFamily(libc::NFPROTO_IPV4 as u8);
pub const TABLE_FAMILY_IP6: TableFamily = TableFamily(libc::NFPROTO_IPV6 as u8);

impl TryFrom<String> for TableFamily {
    type Error = Error;

    fn try_from(value: String) -> Result<TableFamily, Self::Error> {
        match value.as_str() {
            "inet" => Ok(TABLE_FAMILY_INET),
            "ip" => Ok(TABLE_FAMILY_IP),
            "ip6" => Ok(TABLE_FAMILY_IP6),
            _ => Err(Error::UnsupportedTableFamily(value)),
        }
    }
}

impl Display for TableFamily {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                TABLE_FAMILY_INET => "inet",
                TABLE_FAMILY_IP => "ip",
                TABLE_FAMILY_IP6 => "ip6",
                _ => "unknown",
            }
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct Table {
    pub(super) name: String,
    pub(super) family: TableFamily,
}

impl Table {
    pub fn new(name: String, family: TableFamily) -> Table {
        Table {
            name: name + "\0",
            family,
        }
    }

    pub(super) fn get_message(&self) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.message_type =
            ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) + libc::NFT_MSG_GETTABLE as u16;
        hdr.flags = NLM_F_REQUEST;

        let mut msg = NetlinkMessage::new(
            hdr,
            NetlinkPayload::InnerMessage(NetfilterMessage::new(
                NetfilterHeader::new(self.family.0, NFNETLINK_V0, 0),
                NetfilterMessageInner::Other {
                    subsys: 0,
                    message_type: 0,
                    nlas: vec![DefaultNla::new(
                        NFTA_TABLE_NAME,
                        self.name.clone().into_bytes(),
                    )],
                },
            )),
        );
        msg.header.length = msg.buffer_len() as u32;
        msg
    }
}

impl Display for Table {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.family, self.name)
    }
}
