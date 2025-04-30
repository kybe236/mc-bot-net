use crate::packets::PacketDeserialize;

#[derive(Debug)]
pub struct ClientboundPingPacket {
    pub payload: i32,
}

impl PacketDeserialize for ClientboundPingPacket {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        if data.len() < 4 {
            return Err(());
        }

        // Get the 8 bytes for the i64 value (assuming big-endian order)
        let payload_bytes = &data[0..4];

        // Convert the 8 bytes into an i64
        let payload = i32::from_be_bytes(payload_bytes.try_into().expect("Invalid byte length"));

        Ok(ClientboundPingPacket { payload })
    }
}
