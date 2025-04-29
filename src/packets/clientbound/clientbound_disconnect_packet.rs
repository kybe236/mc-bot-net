use crate::{packets::PacketDeserialize, utils::data_types::string::read_string};

#[derive(Debug)]
pub struct ClientboundDisconnectPacket {
    #[allow(unused)]
    pub reason: String,
}

impl PacketDeserialize for ClientboundDisconnectPacket {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        let mut index: usize = 0;
        let reason = read_string(&data, &mut index);
        match reason {
            Ok(reason) => Ok(ClientboundDisconnectPacket { reason }),
            Err(_) => Err(()),
        }
    }
}
