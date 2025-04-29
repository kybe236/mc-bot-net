use crate::packets::PacketDeserialize;

#[derive(Debug)]
pub struct ClientboundFinishConfigurationPacket {}

impl PacketDeserialize for ClientboundFinishConfigurationPacket {
    fn deserialize(_: Vec<u8>) -> Result<Self, ()> {
        Ok(ClientboundFinishConfigurationPacket {})
    }
}
