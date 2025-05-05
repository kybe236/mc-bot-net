use crate::{
    client::State,
    packets::PacketSerialize,
    utils::data_types::{string::write_string, u16::write_u16, varint::write_var_int},
};

/*
 * https://minecraft.wiki/w/Java_Edition_protocol/Packets#Handshake
 */
#[derive(Debug)]
pub struct ServerboundHandshakePacket {
    // The protocol version of the client https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Protocol_version_numbers
    pub protocol_version: i32,
    // The server address used by some anti ddos systems
    pub server_address: String,
    // The server port used by some anti ddos systems
    pub server_port: u16,
    // The next state of the client 1 for Status, 2 for Login, 3 for Transfer.
    pub next_state: i32,
}

impl PacketSerialize for ServerboundHandshakePacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Handshake {
            panic!("Handshake packet can only be sent in the Handshake state");
        }

        let mut buffer = Vec::new();

        write_var_int(&mut buffer, &0x00);

        write_var_int(&mut buffer, &self.protocol_version);
        write_string(&mut buffer, &self.server_address);
        write_u16(&mut buffer, self.server_port);
        write_var_int(&mut buffer, &self.next_state);

        buffer
    }
}
