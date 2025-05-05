use crate::{packets::PacketDeserialize, utils::data_types::varint::read_var_int};

/*
 * https://minecraft.wiki/w/Java_Edition_protocol/Packets#Set_Compression
 */
#[derive(Debug)]
pub struct ClientboundSetCompressionPacket {
    // The threshold for compression. If the packet size is greater than this value, it will be compressed.
    pub threshold: i32,
}

impl PacketDeserialize for ClientboundSetCompressionPacket {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        let mut index: usize = 0;
        let threshold = read_var_int(&data, Some(&mut index));

        Ok(ClientboundSetCompressionPacket { threshold })
    }
}
