use bytemuck::{Pod, Zeroable};

pub const ETHERNET_TYPE_IPV4: u16 = 0x0800;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ty: u16,
}

/*
    0100 | 0101
         |
     ver | len
*/
pub const IPV4_AND_NORMAL_LENGTH: u8 = (4 << 4) | 5;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct IPv4header {
    pub version_and_head_length: u8,
    pub dcsp_and_ecn: u8,
    pub total_len: u16,

    pub identification: u16,
    pub checksum: u16,

    pub src: u32,
    pub dst: u32,
}

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_RESPONSE: u8 = 0;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ICMPheader {
    pub ty: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
    pub timestamp: [u8; 16],
}

pub fn internet_checksum(data: impl Iterator<Item = u16>) -> u16 {
    let mut checksum: u64 = data.map(|x| x as u64).sum();

    if checksum > 0xffff {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    !((checksum & 0xffff) as u16)
}

// Small asm
pub fn slice_as_padded_u16_stream<'a>(data: &'a [u8]) -> impl Iterator<Item = u16> + 'a {
    data.chunks(2)
        .map(|x| {
            let mut y = [0; 2];
            y.iter_mut().zip(x.iter()).for_each(|(y, x)| *y = *x);

            u16::from_ne_bytes(y)
        })
}