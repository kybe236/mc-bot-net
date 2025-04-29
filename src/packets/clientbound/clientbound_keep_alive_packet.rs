use crate::packets::PacketDeserialize;

#[derive(Debug)]
pub struct ClientboundKeepAlivePacket {
    pub keep_alive_id: i64,
}

impl PacketDeserialize for ClientboundKeepAlivePacket {
    fn deserialize(data: Vec<u8>) -> Result<ClientboundKeepAlivePacket, ()> {
        if data.len() < 8 {
            return Err(());
        }

        // Get the 8 bytes for the i64 value (assuming big-endian order)
        let keep_alive_id_bytes = &data[0..8];

        // Convert the 8 bytes into an i64
        let keep_alive_id =
            i64::from_be_bytes(keep_alive_id_bytes.try_into().expect("Invalid byte length"));

        Ok(ClientboundKeepAlivePacket { keep_alive_id })
    }
}
