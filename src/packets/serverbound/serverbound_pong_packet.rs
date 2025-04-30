use crate::{client::State, packets::PacketSerialize, utils::data_types::varint::write_var_int};

#[derive(Debug)]
pub struct ServerboundPongPacket {
    pub payload: i32,
}

impl PacketSerialize for ServerboundPongPacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Play {
            panic!("Pong packet can only be sent in the Play state");
        }
        let mut buffer = Vec::new();
        write_var_int(&mut buffer, &0x2B);
        write_var_int(&mut buffer, &self.payload);

        buffer
    }
}
