use crate::{client::State, packets::PacketSerialize, utils::data_types::varint::write_var_int};

#[derive(Debug)]
pub struct ServerboundAcknowledgeFinishConfigurationPacket {}

impl PacketSerialize for ServerboundAcknowledgeFinishConfigurationPacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Play {
            panic!("Acknowledge Finish Configuration packet can only be sent in the Play state");
        }
        let mut buffer = Vec::new();
        write_var_int(&mut buffer, &0x03);

        buffer
    }
}
