use crate::{packets::PacketDeserialize, utils::data_types::varint::read_var_int};

#[derive(Debug)]
pub struct ClientboundSetCompressionPacket {
    pub threshold: i32,
}

impl PacketDeserialize for ClientboundSetCompressionPacket {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        let mut index: usize = 0;
        let threshold = read_var_int(&data, Some(&mut index));

        Ok(ClientboundSetCompressionPacket { threshold })
    }
}
