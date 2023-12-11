use std::net::Ipv4Addr;

use bytes::{BufMut, Buf, BytesMut};
use etherparse::{Ethernet2Header, Ipv4Header, Icmpv4Header, SerializedSize};
use etherparse::{ip_number, ether_type, IcmpEchoHeader};
use thiserror::Error;

const ICMP_HEADER_LEN: usize = 24;

#[derive(Clone, Copy)]
pub struct NetworkCfg {
    pub client_mac: [u8; 6],
    pub server_mac: [u8; 6],
    pub server_ip: Ipv4Addr,
    pub client_ip: Ipv4Addr,
}

type HandshakeStr = [u8; 8];
static HANDSHAKE_STR : HandshakeStr = [
    0xde, 0xad,
    0xbe, 0xef,
    0xde, 0xad,
    0xbe, 0xef,
];

// TODO: add timestamp: [0; 16],
#[derive(PartialEq, Eq, Clone)]
pub struct PacketHeader {
    pub eth: Ethernet2Header,
    pub ipv4: Ipv4Header,
    pub icmpv4: Icmpv4Header,
}

impl PacketHeader {
    pub const HEADER_LEN: usize =
        Ethernet2Header::SERIALIZED_SIZE +
        Ipv4Header::SERIALIZED_SIZE +
        ICMP_HEADER_LEN;

    pub fn new(cfg: NetworkCfg) -> Self {
        PacketHeader {
            eth: Ethernet2Header {
                source: cfg.client_mac,
                destination: cfg.server_mac,
                ether_type: ether_type::IPV4,
            },
            ipv4: Ipv4Header::new(
                0,
                64, // TODO: configure?
                ip_number::ICMP,
                cfg.client_ip.octets(),
                cfg.server_ip.octets(),
            ),
            icmpv4: Icmpv4Header {
                icmp_type: etherparse::Icmpv4Type::EchoRequest(IcmpEchoHeader {
                    id: 0xfff,
                    seq: 0xffff,
                }),
                checksum: 0,
            },
        }
    }

    pub fn from_bytes<B: Buf>(bytes: &mut B) -> Result<Self, ParseError> {
        if bytes.remaining() < Self::HEADER_LEN {
            return Err(ParseError::BufferTooSmall);
        }

        let eth = {
            let mut buff = [0u8; Ethernet2Header::SERIALIZED_SIZE];
            bytes.copy_to_slice(&mut buff);
            Ethernet2Header::from_bytes(buff)
        };
        let ipv4 = {
            let mut buff = [0u8; Ipv4Header::SERIALIZED_SIZE];
            bytes.copy_to_slice(&mut buff);
            Ipv4Header::from_slice(&buff)
                .map_err(|_| ParseError::InvalidPacket)?.0
        };
        let icmpv4 = {
            let mut buff = [0u8; ICMP_HEADER_LEN];
            bytes.copy_to_slice(&mut buff);
            Icmpv4Header::from_slice(&buff)
                .map_err(|_| ParseError::InvalidPacket)?.0
        };

        Ok(PacketHeader { eth, ipv4, icmpv4 })
    }

    pub fn write_bytes<B: BufMut>(&self, buff: &mut B) {
        assert!(buff.remaining_mut() < Self::HEADER_LEN, "Write buffer is too small");

        buff.put_slice(&self.eth.to_bytes());
        self.ipv4.write(&mut buff.writer()).unwrap();
        buff.put_slice(&self.icmpv4.to_bytes());
    }

    pub fn update_for_payload(&mut self, payload: &[u8]) {
        self.ipv4.payload_len = payload.len() as u16;
        self.update_checksum(payload);
    }

    #[inline]
    fn update_checksum(&mut self, payload: &[u8]) {
        // TODO: is that okay?
        self.ipv4.header_checksum = self.ipv4.calc_header_checksum().unwrap();

        self.icmpv4.checksum = 0;
        self.icmpv4.update_checksum(payload);
    }
}

#[derive(Debug, Clone, Copy, Error)]
#[repr(u8)]
pub enum ParseError {
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Ill formed packet")]
    InvalidPacket,
    #[error("Handshake was expected")]
    ExpectedHandshake,
}

#[derive(Debug, Clone, Copy, Error)]
#[repr(u8)]
pub enum PutError {
    #[error("The encryption key hasn't been acquired yet")]
    NoKey,
    #[error("Supplied buffer is not big enough")]
    BufferTooSmall,
}

#[derive(Clone, Copy)]
pub struct VpnCfg {
    pub virt_ip: u32,
    pub subnet_mask: u32,
    pub key: u64,
}

#[derive(Clone, Copy)]
enum ProtoState {
    Handshake,
    HandshakeDone(VpnCfg),
}

pub struct ProtoContext {
    head: PacketHeader,
    state: ProtoState,
    buffer: BytesMut,
}

impl ProtoContext {
    pub fn new(cfg: NetworkCfg) -> Self {
        ProtoContext {
            head: PacketHeader::new(cfg),
            state: ProtoState::Handshake,
            buffer: BytesMut::with_capacity(100),
        }
    }

    pub fn parse_packet<B: Buf>(
        &mut self,
        payload: &mut B,
    ) -> Result<Option<&[u8]>, ParseError> {
        let header = PacketHeader::from_bytes(payload)?;
        let enc_payload = payload.copy_to_bytes(
            header.ipv4.payload_len as usize - header.icmpv4.header_len()
        );

        /* Construct a sample of the expected header */
        let mut expect_head = self.head.clone();
        std::mem::swap(&mut expect_head.eth.source, &mut expect_head.eth.destination);
        std::mem::swap(&mut expect_head.ipv4.source, &mut expect_head.ipv4.destination);
        expect_head.ipv4.payload_len = header.ipv4.payload_len;
        expect_head.icmpv4.icmp_type = etherparse::Icmpv4Type::EchoReply(IcmpEchoHeader {
            id: 0xfff,
            seq: 0xffff,
        });
        expect_head.update_checksum(&enc_payload);

        if header != expect_head {
            return Err(ParseError::InvalidPacket);
        }

        /* Process the data */
        match self.state {
            ProtoState::Handshake => {
                if payload.remaining() < std::mem::size_of::<VpnCfg>() {
                    return Err(ParseError::BufferTooSmall);
                }
                self.apply_network_cfg(VpnCfg {
                    virt_ip: payload.get_u32(),
                    subnet_mask: payload.get_u32(),
                    key: payload.get_u64(),
                });

                Ok(None)
            },
            ProtoState::HandshakeDone(cfg) => {
                /* Now read the payload len */
                if payload.remaining() < 2 {
                    return Err(ParseError::BufferTooSmall);
                }
                let true_payload_len = payload.get_u16() as usize;

                /* Now decrypt the payload */
                let read = self.decrypt(payload, cfg.key, true_payload_len as u16);
                if read < true_payload_len {
                    return Err(ParseError::BufferTooSmall);
                }

                Ok(Some(&self.buffer))
            },
        }
    }

    pub fn reset(&mut self) {
        tracing::debug!("Reset connection");

        self.state = ProtoState::Handshake;
    }

    pub fn write_handshake<B: BufMut>(
        &mut self,
        buff: &mut B,
    ) -> Result<(), PutError> {
        /* Handshake payload: header + handshake_str */
        let payload_len = HANDSHAKE_STR.len();
        let expect_len = std::mem::size_of::<PacketHeader>() + payload_len;
        if buff.remaining_mut() < expect_len {
            return Err(PutError::BufferTooSmall)
        }

        /* Prepare header */
        self.head.update_for_payload(&HANDSHAKE_STR);

        /* Write */
        self.head.write_bytes(buff);
        buff.put_slice(&HANDSHAKE_STR);

        Ok(())
    }

    pub fn write_payload<B: BufMut>(
        &mut self,
        mut payload: &[u8],
        buff: &mut B,
    ) -> Result<(), PutError> {
        /* Better check the key first */
        let key = match &self.state {
            ProtoState::HandshakeDone(x) => x.key,
            _ => return Err(PutError::NoKey),
        };
        self.encrypt(&mut payload, key);

        /* Prepare header */
        let actual_len = payload.len() as u16;
        self.head.update_for_payload(&self.buffer);

        /* Write */
        self.head.write_bytes(buff);
        buff.put_u16(actual_len);
        buff.put_slice(&self.buffer);

        Ok(())
    }

    pub fn network_cfg(&self) -> Option<&VpnCfg> {
        match &self.state {
            ProtoState::Handshake => None,
            ProtoState::HandshakeDone(x) => Some(x),
        }
    }

    fn apply_network_cfg(&mut self, cfg: VpnCfg) {
        let virt_addr = Ipv4Addr::from(cfg.virt_ip);
        let net_addr = Ipv4Addr::from(cfg.virt_ip | cfg.subnet_mask);
        let mask = cfg.subnet_mask;
        tracing::debug!("Network cfg: myip={virt_addr}\tsubnet={net_addr}/{mask}");

        self.state = ProtoState::HandshakeDone(cfg);
    }

    #[inline]
    fn decrypt<B: Buf>(
        &mut self,
        payload: &mut B,
        key: u64,
        real_len: u16,
    ) -> usize {
        debug_assert!(payload.remaining() % 8 == 0);
        let mut put = 0;

        self.buffer.clear();
        std::iter::from_fn(||
            payload.has_remaining().then(|| payload.get_u64())
        )
            .map(|block| block ^ key)
            .flat_map(u64::to_ne_bytes)
            .take(real_len as usize)
            .for_each(|b| { put += 1; self.buffer.put_u8(b) });

       put
    }

    #[inline]
    fn encrypt<B: Buf>(
        &mut self,
        payload: &mut B,
        key: u64,
    ) -> usize {
        let mut put = 0;
        self.buffer.clear();

        std::iter::from_fn(|| payload.has_remaining().then(|| {
            let mut buff = [0u8; 8];
            let len = std::cmp::min(8, payload.remaining());

            payload.copy_to_slice(&mut buff[0..len]);
            buff
        }))
            .map(u64::from_ne_bytes)
            .map(|x| x ^ key)
            .for_each(|x| { put += 8; self.buffer.put_u64(x) });

        put
    }

}