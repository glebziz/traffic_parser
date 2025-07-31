#![allow(unused)]

mod constants;
mod ipset;
mod table;

use crate::detector::IpSetAdder;
use crate::errors::Error;
use crate::nft::constants::*;
pub use crate::nft::ipset::IpSet;
pub use crate::nft::table::{TABLE_FAMILY_INET, Table, TableFamily};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_netfilter::constants::NFNETLINK_V0;
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterMessageInner};
use netlink_packet_utils::Emitable;
use netlink_packet_utils::nla::DefaultNla;
use netlink_sys::Socket;
use netlink_sys::constants::NETLINK_NETFILTER;
use std::net::IpAddr;

pub struct Connection {
    conn: Socket,
}
impl Connection {
    pub fn new() -> Result<Connection, Error> {
        let mut conn = match Socket::new(NETLINK_NETFILTER) {
            Ok(socket) => socket,
            Err(err) => return Err(Error::External(err.to_string())),
        };

        match conn.bind_auto() {
            Ok(_) => {}
            Err(err) => return Err(Error::External(err.to_string())),
        }

        match conn.set_non_blocking(true) {
            Ok(_) => {}
            Err(err) => return Err(Error::External(err.to_string())),
        }

        Ok(Connection { conn })
    }

    pub fn check_table(&mut self, table: &Table) -> Result<(), Error> {
        match self.send_one(table.get_message()) {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Err(Error::TableNotFound(format!("\"{table}\""))),
            Err(err) => Err(err),
        }
    }

    pub fn check_ipset(&mut self, table: &Table, ipset: &IpSet) -> Result<(), Error> {
        match self.send_one(ipset.get_message(table)) {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Err(Error::IpSetNotFound(format!(
                "\"{} {}\"",
                table,
                ipset.name.clone()
            ))),
            Err(err) => Err(err),
        }
    }

    fn send_one(&self, msg: NetlinkMessage<NetfilterMessage>) -> Result<(), Error> {
        match self.send(vec![msg]) {
            Ok(_) => {}
            Err(err) => return Err(err),
        };

        self.check_response(self.recv_msg()?)
    }

    fn send_batch(&self, msgs: Vec<NetlinkMessage<NetfilterMessage>>) -> Result<(), Error> {
        let mut batch = vec![self.begin_batch_message()];
        batch.extend_from_slice(msgs.as_slice());
        batch.push(self.end_batch_message());

        match self.send(batch) {
            Ok(_) => {}
            Err(err) => return Err(err),
        }

        match self.recv_all() {
            Ok(_) => {}
            Err(err) => return Err(err),
        }

        Ok(())
    }

    fn send(&self, msgs: Vec<NetlinkMessage<NetfilterMessage>>) -> Result<(), Error> {
        let mut buf = vec![0; msgs.iter().map(|msg| msg.header.length as usize).sum()];

        let mut offset = 0;
        msgs.iter().for_each(|msg| {
            msg.serialize(&mut buf[offset..offset + msg.header.length as usize]);
            offset += msg.header.length as usize;
        });

        match self.conn.send(&buf[..], 0) {
            Ok(_) => Ok(()),
            Err(err) => Err(Error::External(err.to_string())),
        }
    }

    fn recv_msg(&self) -> Result<NetlinkMessage<NetfilterMessage>, Error> {
        let res = match self.recv_all() {
            Ok(res) => res,
            Err(err) => return Err(Error::External(err.to_string())),
        };

        match <NetlinkMessage<NetfilterMessage>>::deserialize(&res[..]) {
            Ok(resp) => Ok(resp),
            Err(err) => Err(Error::External(err.to_string())),
        }
    }

    fn recv_all(&self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; 1024];
        let mut out = Vec::default();
        loop {
            match self.conn.recv(&mut &mut buf[..], 0) {
                Ok(0) => break,
                Ok(len) => out.extend_from_slice(&buf[..len]),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(Error::External(err.to_string())),
            };
        }

        Ok(out)
    }

    fn check_response(&self, resp: NetlinkMessage<NetfilterMessage>) -> Result<(), Error> {
        match resp.payload {
            NetlinkPayload::<_>::Error(err) => match err.code {
                Some(code) => match code.abs().get() {
                    1 => Err(Error::PermissionDenied),
                    2 => Err(Error::NotFound),
                    _ => Err(Error::External(err.to_string())),
                },
                None => Err(Error::External(err.to_string())),
            },
            _ => Ok(()),
        }
    }

    fn encode_nlas(&self, nlas: Vec<DefaultNla>) -> Vec<u8> {
        let mut out = vec![0; nlas.as_slice().buffer_len()];
        nlas.as_slice().emit(&mut out[..]);
        out
    }

    fn ip_data(&self, ip: &IpAddr) -> Vec<u8> {
        self.encode_nlas(vec![match ip {
            IpAddr::V4(ip) => DefaultNla::new(NFTA_DATA_VALUE, ip.octets().to_vec()),
            IpAddr::V6(ip) => DefaultNla::new(NFTA_DATA_VALUE, ip.octets().to_vec()),
        }])
    }

    fn item_data(&self, ip: &IpAddr) -> Vec<u8> {
        self.encode_nlas(vec![DefaultNla::new(
            NFTA_SET_ELEM_KEY | NLA_F_NESTED,
            self.ip_data(ip),
        )])
    }

    fn element_data(&self, ip: &IpAddr) -> Vec<u8> {
        self.encode_nlas(vec![DefaultNla::new(1 | NLA_F_NESTED, self.item_data(ip))])
    }

    fn add_ip_message(
        &self,
        table: &Table,
        ipset: &IpSet,
        ip: &IpAddr,
    ) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.message_type =
            ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) + libc::NFT_MSG_NEWSETELEM as u16;
        hdr.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

        let mut msg = NetlinkMessage::new(
            hdr,
            NetlinkPayload::InnerMessage(NetfilterMessage::new(
                NetfilterHeader::new(table.family.0, NFNETLINK_V0, 0),
                NetfilterMessageInner::Other {
                    subsys: 0,
                    message_type: 0,
                    nlas: vec![
                        DefaultNla::new(NFTA_SET_ELEM_LIST_SET, ipset.name.clone().into_bytes()),
                        DefaultNla::new(NFTA_SET_ELEM_LIST_SET_ID, vec![0, 0, 0, 0]),
                        DefaultNla::new(NFTA_SET_ELEM_LIST_TABLE, table.name.clone().into_bytes()),
                        DefaultNla::new(
                            NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED,
                            self.element_data(ip),
                        ),
                    ],
                },
            )),
        );
        msg.header.length = msg.buffer_len() as u32;
        msg
    }

    fn begin_batch_message(&self) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.message_type = libc::NFNL_MSG_BATCH_BEGIN as u16;
        hdr.flags = NLM_F_REQUEST;

        self.batch_message(hdr)
    }

    fn end_batch_message(&self) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.message_type = libc::NFNL_MSG_BATCH_END as u16;
        hdr.flags = NLM_F_REQUEST;

        self.batch_message(hdr)
    }

    fn batch_message(&self, hdr: NetlinkHeader) -> NetlinkMessage<NetfilterMessage> {
        let mut msg = NetlinkMessage::new(
            hdr,
            NetlinkPayload::InnerMessage(NetfilterMessage::new(
                NetfilterHeader::new(0, NFNETLINK_V0, libc::NFNL_SUBSYS_NFTABLES as u16),
                NetfilterMessageInner::Other {
                    subsys: 0,
                    message_type: 0,
                    nlas: vec![],
                },
            )),
        );
        msg.header.length = msg.buffer_len() as u32;
        msg
    }
}

impl IpSetAdder for Connection {
    fn add_ip(&self, table: &Table, ipset: &IpSet, ip: &IpAddr) -> Result<(), Error> {
        match self.send_batch(vec![self.add_ip_message(table, ipset, ip)]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
}
