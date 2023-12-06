use std::net::Ipv4Addr;

use super::util::*;
use bytemuck::{Pod, Zeroable};
use bytes::{BufMut, Buf};
use thiserror::Error;

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

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct PacketHeader {
    pub eth: EthHeader,
    pub ipv4: IPv4header,
    pub icmp: ICMPheader,
}

impl PacketHeader {
    pub fn new(cfg: NetworkCfg) -> Self {
        PacketHeader {
            eth: EthHeader {
                dst: cfg.client_mac,
                src: cfg.server_mac,
                ty: ETHERNET_TYPE_IPV4,
            },
            ipv4: IPv4header {
                version_and_head_length: IPV4_AND_NORMAL_LENGTH,
                dcsp_and_ecn: 0, // Zeroed (cuz deprecated) + no CN
                total_len: 0,
                identification: 0,
                checksum: 0,
                src: u32::from_ne_bytes(cfg.client_ip.octets()),
                dst: u32::from_ne_bytes(cfg.server_ip.octets()),
            },
            icmp: ICMPheader {
                ty: ICMP_ECHO_REQUEST,
                code: 0,
                checksum: 0,
                id: 0xffff,
                seq: 0xffff,
                timestamp: [0; 16],
            },
        }
    }

    pub fn change_for_payload(
        &mut self,
        actual_payload_len: u16,
        payload: impl Iterator<Item = u16>,
    ) {
        self.apply_payload_len(actual_payload_len);
        self.apply_checksum(payload);
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Option<&PacketHeader> {
        bytemuck::try_from_bytes(bytes).ok()
    }

    #[inline]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> Option<&mut PacketHeader> {
        bytemuck::try_from_bytes_mut(bytes).ok()
    }

    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    #[inline]
    fn apply_payload_len(&mut self, payload_len: u16) {
        self.ipv4.total_len =
            std::mem::size_of::<IPv4header>() as u16 +
            std::mem::size_of::<ICMPheader>() as u16 +
            payload_len;
    }

    #[inline]
    fn apply_ipv4_checksum(&mut self) {
        self.ipv4.checksum = 0;
        self.ipv4.checksum = internet_checksum(
            slice_as_padded_u16_stream(bytemuck::bytes_of(&self.ipv4))
        );
    }

    #[inline]
    fn apply_checksum(&mut self, icmp_data: impl Iterator<Item = u16>) {
        self.apply_ipv4_checksum();

        self.icmp.checksum = 0;
        self.icmp.checksum = internet_checksum(
            slice_as_padded_u16_stream(bytemuck::bytes_of(&self.icmp))
            .chain(icmp_data)
        );
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

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
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
}

impl ProtoContext {
    pub fn new(cfg: NetworkCfg) -> Self {
        ProtoContext {
            head: PacketHeader::new(cfg),
            state: ProtoState::Handshake,
        }
    }

    pub fn parse_packet<B: Buf, P: BufMut>(
        &mut self,
        buff: &mut B,
        payload: &mut P,
    ) -> Result<usize, ParseError> {
        let packet_len = buff.remaining();

        if packet_len < std::mem::size_of::<PacketHeader>() {
            return Err(ParseError::BufferTooSmall);
        }

        let mut header = PacketHeader::zeroed();
        buff.copy_to_slice(bytemuck::bytes_of_mut(&mut header));

        /* Construct a sample of the expected header */
        let mut expect_head = self.head;
        std::mem::swap(&mut expect_head.eth.src, &mut expect_head.eth.dst);
        let temp = expect_head.ipv4.src;
        expect_head.ipv4.total_len = (packet_len - std::mem::size_of::<EthHeader>()) as u16;
        expect_head.ipv4.src = expect_head.ipv4.dst;
        expect_head.ipv4.dst = temp;
        expect_head.icmp.ty = ICMP_ECHO_RESPONSE;
        expect_head.apply_ipv4_checksum();

        /* Compare to the sample, but don't check icmp checksum YET */
        let head_l = bytemuck::bytes_of(&header);
        let head_r = bytemuck::bytes_of(&expect_head);
        if &head_l[0..32] != &head_r[0..32] {
            return Err(ParseError::InvalidPacket);
        }
        if &head_l[34..54] != &head_r[34..54] {
            return Err(ParseError::InvalidPacket);
        }

        match self.state {
            ProtoState::Handshake => {
                let cfg = Self::read_handshake(buff)?;
                self.apply_network_cfg(cfg);

                Ok(0)
            },
            ProtoState::HandshakeDone(cfg) => Self::read_payload(buff, payload, cfg.key),
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
        self.head.change_for_payload(
            payload_len as u16,
            slice_as_padded_u16_stream(&HANDSHAKE_STR),
        );

        /* Write */
        buff.put_slice(self.head.as_bytes());
        buff.put_slice(&HANDSHAKE_STR);

        Ok(())
    }

    pub fn write_payload<B: BufMut>(
        &mut self,
        payload: &[u8],
        buff: &mut B,
    ) -> Result<(), PutError> {
        /* Better check the key first */
        let key = match &self.state {
            ProtoState::HandshakeDone(x) => x.key,
            _ => return Err(PutError::NoKey),
        };

        /* Normal payload: header + 2 + padded data */
        let mut payload_len = payload.len();
        payload_len += payload_len % 4;
        let expect_len = 2 + std::mem::size_of::<PacketHeader>() + payload_len;
        if buff.remaining_mut() <= expect_len {
            return Err(PutError::BufferTooSmall)
        }

        /* Prepare header */
        let actual_len = payload.len() as u16;
        self.head.change_for_payload(
            actual_len,
            Self::split_u64(
                Self::encrypt(Self::blocky_bytes(payload), key)
            )
        );

        /* Write */
        buff.put_slice(self.head.as_bytes());
        buff.put_u16(actual_len);
        Self::encrypt(Self::blocky_bytes(payload), key)
            .for_each(|block| buff.put_u64_ne(block));

        Ok(())
    }

    pub fn network_cfg(&self) -> Option<&VpnCfg> {
        match &self.state {
            ProtoState::Handshake => None,
            ProtoState::HandshakeDone(x) => Some(x),
        }
    }

    fn read_handshake<B: Buf>(
        buff: &mut B,
    ) -> Result<VpnCfg, ParseError> {
        if buff.remaining() < std::mem::size_of::<VpnCfg>() {
            return Err(ParseError::BufferTooSmall);
        }

        let mut cfg = VpnCfg::zeroed();
        buff.copy_to_slice(bytemuck::bytes_of_mut(&mut cfg));

        Ok(cfg)
    }

    fn read_payload<B: Buf, P: BufMut>(
        buff: &mut B,
        payload: &mut P,
        key: u64,
    ) -> Result<usize, ParseError> {
        /* Now read the payload len */
        let mut payload_len = buff.remaining();
        if payload_len < 2 {
            return Err(ParseError::BufferTooSmall);
        }
        payload_len -= 2;
        let true_payload_len = buff.get_u16() as usize;
        if payload_len != (true_payload_len + true_payload_len % 8) {
            return Err(ParseError::BufferTooSmall); // Sanity check ;)
        }

        /* Now decrypt the payload */
        if payload.remaining_mut() < true_payload_len {
            return Err(ParseError::BufferTooSmall);
        }
        let block_stream = std::iter::from_fn(||
            buff.has_remaining().then(|| buff.get_u64_ne())
        );
        let block_stream = Self::decrypt(block_stream, key);
        // Might be slow, but was the simplest thing to do
        let mut cnt = 0;
        block_stream.flat_map(u64::to_le_bytes).take(true_payload_len)
            .for_each(|x| { payload.put_u8(x); cnt += 1 });
        debug_assert!(cnt == true_payload_len); // One more sanity check

        Ok(true_payload_len)
    }

    fn apply_network_cfg(&mut self, cfg: VpnCfg) {
        let virt_addr = Ipv4Addr::from(cfg.virt_ip);
        let net_addr = Ipv4Addr::from(cfg.virt_ip | cfg.subnet_mask);
        let mask = cfg.subnet_mask;
        tracing::debug!("Network cfg: myip={virt_addr}\tsubnet={net_addr}/{mask}");

        self.state = ProtoState::HandshakeDone(cfg);
    }

    fn blocky_bytes<'a>(bytes: &'a [u8]) -> impl Iterator<Item = u64> + 'a {
        bytes.chunks(4)
            .map(|x| {
                let mut y = [0; 8]; // TODO random padding
                y.iter_mut().zip(x.iter()).for_each(|(y, x)| *y = *x);

                u64::from_ne_bytes(y)
            })
    }

    #[inline]
    fn split_u64(it: impl Iterator<Item = u64>) -> impl Iterator<Item = u16> {
        it.map(|x| x.to_ne_bytes())
        .flat_map(|x| [
            [x[0], x[1]],
            [x[2], x[3]],
            [x[4], x[5]],
            [x[6], x[7]],
        ].map(u16::from_ne_bytes))
    }

    #[inline]
    fn decrypt(payload: impl Iterator<Item = u64>, key: u64) -> impl Iterator<Item = u64> {
        Self::encrypt(payload, key)
    }

    #[inline]
    fn encrypt(payload: impl Iterator<Item = u64>, key: u64) -> impl Iterator<Item = u64> {
        payload.map(move |x| x ^ key)
    }

}