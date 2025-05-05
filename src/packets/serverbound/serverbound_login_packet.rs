use crate::{
    client::State,
    packets::PacketSerialize,
    utils::data_types::{string::write_string, uuid::write_uuid, varint::write_var_int},
};

/*
 * https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Start
 */
#[derive(Debug)]
pub struct ServerboundLoginPacket {
    // The username of the client
    pub username: String,
    // The UUID of the client for cracked genreated via name
    pub uuid: u128,
}

impl PacketSerialize for ServerboundLoginPacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Login {
            panic!("Login packet can only be sent in the Login state");
        }

        let mut buffer = Vec::new();
        write_var_int(&mut buffer, &0x00);
        write_string(&mut buffer, &self.username);
        write_uuid(&mut buffer, self.uuid);

        buffer
    }
}
