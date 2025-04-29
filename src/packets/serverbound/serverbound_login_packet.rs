use crate::{
    client::State,
    packets::PacketSerialize,
    utils::data_types::{string::write_string, uuid::write_uuid, varint::write_var_int},
};

#[derive(Debug)]
pub struct ServerboundLoginPacket {
    pub username: String,
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
