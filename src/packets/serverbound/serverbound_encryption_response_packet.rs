use crate::{client::State, packets::PacketSerialize, utils::data_types::varint::write_var_int};

/*
 * https://minecraft.wiki/w/Java_Edition_protocol/Packets#Encryption_Response
 */
#[derive(Debug)]
pub struct ServerboundEncryptionResponsePacket {
    // Shared Secret value, encrypted with the server's public key.
    pub shared_secret: Vec<u8>,
    // Verify Token value, encrypted with the same public key as the shared secret.
    pub verify_token: Vec<u8>,
}

impl PacketSerialize for ServerboundEncryptionResponsePacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Login {
            panic!("Encryption Response packet can only be sent in the Login state");
        }
        let mut buffer = Vec::new();
        write_var_int(&mut buffer, &0x01);
        write_var_int(&mut buffer, &(self.shared_secret.len() as i32));
        buffer.append(&mut self.shared_secret.clone());
        write_var_int(&mut buffer, &(self.verify_token.len() as i32));
        buffer.append(&mut self.verify_token.clone());

        buffer
    }
}
