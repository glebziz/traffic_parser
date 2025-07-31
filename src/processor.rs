use crate::packet::Packet;
use mockall::automock;
use rtest::test_cases;

#[automock]
pub trait PacketProcessor {
    fn process(&self, packet: &Packet);
}

pub struct Processor<'a> {
    processors: Vec<&'a dyn PacketProcessor>,
}

impl<'a> Processor<'a> {
    pub fn new() -> Processor<'a> {
        Processor {
            processors: Vec::new(),
        }
    }

    pub fn add_processor<T: PacketProcessor>(&mut self, packet_processor: &'a T) {
        self.processors.push(packet_processor);
    }

    pub fn process(&mut self, data: &[u8]) {
        let p = match Packet::parse(data) {
            Some(p) => p,
            None => return,
        };

        self.processors.iter().for_each(|pp| (*pp).process(&p));
    }
}

test_cases!(process => vars{
    use mockall::predicate;
    use crate::packet::{Packet, IpPacket, IpPayload};
    use std::net::{IpAddr, Ipv4Addr};

    const INVALID_DATA: &[u8] = &[0x00, 0x01, 0x02, 0x03];
    const DATA: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x08, 0x00, 0x45, 0xc0,
        0x00, 0x14, 0xe3, 0x71, 0x00, 0x00, 0xff, 0xff,
        0x31, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07,
    ];

    const PKT: Packet = Packet::Ip(IpPacket {
            src: IpAddr::V4(Ipv4Addr::new(0x00, 0x01, 0x02, 0x03)),
            dst: IpAddr::V4(Ipv4Addr::new(0x04, 0x05, 0x06, 0x07)),
            payload: IpPayload::Other(vec![]),
        });
}, cases{
    struct TestCase{
        processors: Vec<MockPacketProcessor>,
        data: &'static [u8],
    }
}[
    case(invalid_data, TestCase{
        processors: vec![MockPacketProcessor::new()],
        data: INVALID_DATA,
    }),
    case(data, TestCase{
        processors: {
            let mut p = MockPacketProcessor::new();
            p.expect_process()
                .with(predicate::eq(PKT))
                .once()
                .return_const(());

            let mut p2 = MockPacketProcessor::new();
            p2.expect_process()
                .with(predicate::eq(PKT))
                .once()
                .return_const(());

            vec![p, p2]
        },
        data: DATA,
    })
] => |tc: TestCase| {
    let mut p = Processor::new();
    for i in 0..tc.processors.len() {
        p.add_processor(&tc.processors[i])
    }

    p.process(tc.data);
});
