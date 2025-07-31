use crate::nft::Table;
use crate::nft::constants::*;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_netfilter::constants::NFNETLINK_V0;
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterMessageInner};
use netlink_packet_utils::nla::DefaultNla;

#[derive(Debug, PartialEq)]
pub struct IpSet {
    pub(super) name: String,
}

impl IpSet {
    pub fn new(name: String) -> IpSet {
        IpSet { name: name + "\0" }
    }

    pub(super) fn get_message(&self, table: &Table) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.message_type = ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) + libc::NFT_MSG_GETSET as u16;
        hdr.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut msg = NetlinkMessage::new(
            hdr,
            NetlinkPayload::InnerMessage(NetfilterMessage::new(
                NetfilterHeader::new(table.family.0, NFNETLINK_V0, 0),
                NetfilterMessageInner::Other {
                    subsys: 0,
                    message_type: 0,
                    nlas: vec![
                        DefaultNla::new(NFTA_SET_TABLE, table.name.clone().into_bytes()),
                        DefaultNla::new(NFTA_SET_NAME, self.name.clone().into_bytes()),
                    ],
                },
            )),
        );
        msg.header.length = msg.buffer_len() as u32;
        msg
    }
}
