use byteorder::{BigEndian, ByteOrder, LittleEndian};

/// 网络字节序统一为大端序，主机字节序通常是小端

#[allow(unused)]
pub fn l2b_u32(l: u32) -> u32 {
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, l);
    BigEndian::read_u32(&buf)
}

pub fn l2b_u16(l: u16) -> u16 {
    let mut buf = [0u8; 2];
    LittleEndian::write_u16(&mut buf, l);
    BigEndian::read_u16(&buf)
}

pub fn b2l_u16(b: u16) -> u16 {
    let mut buf = [0u8; 2];
    LittleEndian::write_u16(&mut buf, b);
    BigEndian::read_u16(&buf)
}

pub fn b2l_u32(b: u32) -> u32 {
    let mut buf = [0u8; 4];
    BigEndian::write_u32(&mut buf, b);
    LittleEndian::read_u32(&buf)
}

pub fn b2l_u128_array(buf: &[u8; 16]) -> u128 {
    LittleEndian::read_u128(buf)
}
