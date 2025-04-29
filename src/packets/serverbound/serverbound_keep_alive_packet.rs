use crate::{client::State, packets::PacketSerialize, utils::data_types::varint::write_var_int};

#[derive(Debug)]
pub struct ServerboundKeepAlivePacket {
    pub keep_alive_id: i64,
}

impl PacketSerialize for ServerboundKeepAlivePacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Play && *state != State::Configuration {
            panic!("Keep Alive packet can only be sent in the Play state");
        }
        let mut buffer = Vec::new();

        let id = if *state == State::Play { 0x18 } else { 0x04 };

        write_var_int(&mut buffer, &id);
        buffer.append(&mut self.keep_alive_id.to_be_bytes().to_vec());

        buffer
    }
}
