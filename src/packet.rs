use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum PacketType {
    ServerBound,
    ClientBound,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Packet {
    pub data: Vec<u8>,
}
