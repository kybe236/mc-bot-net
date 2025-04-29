use crate::{
    client::State,
    packets::PacketSerialize,
    utils::data_types::{string::write_string, u16::write_u16, varint::write_var_int},
};

#[derive(Debug)]
pub struct ServerboundHandshakePacket {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

impl PacketSerialize for ServerboundHandshakePacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Handshake {
            panic!("Handshake packet can only be sent in the Handshake state");
        }

        let mut buffer = Vec::new();

        // Write the packet ID (0x00 for Handshake)
        write_var_int(&mut buffer, &0x00);

        // Write the protocol version, server address, and port aswell as the next state
        write_var_int(&mut buffer, &self.protocol_version);
        write_string(&mut buffer, &self.server_address);
        write_u16(&mut buffer, self.server_port);
        write_var_int(&mut buffer, &self.next_state);

        buffer
    }
}
