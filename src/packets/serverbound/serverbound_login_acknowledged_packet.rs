use crate::{client::State, packets::PacketSerialize, utils::data_types::varint::write_var_int};

/*
 * https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Acknowledged
 */
#[derive(Debug)]
pub struct ServerboundLoginAcknowledgedPacket {}

impl PacketSerialize for ServerboundLoginAcknowledgedPacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Login {
            panic!("Login Acknowledged packet can only be sent in the Login state");
        }
        let mut buffer = Vec::new();
        write_var_int(&mut buffer, &0x03);

        buffer
    }
}
