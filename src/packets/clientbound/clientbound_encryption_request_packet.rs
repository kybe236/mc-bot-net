use crate::{
    packets::PacketDeserialize,
    utils::data_types::{boolean::read_boolean, string::read_string, varint::read_var_int},
};

/*
 * https://minecraft.wiki/w/Java_Edition_protocol/Packets#Encryption_Request
 */
#[derive(Debug)]
pub struct ClientboundEncryptionRequestPacket {
    // UNUSED
    #[allow(unused)]
    pub server_id: String,
    // The public key of the server
    pub public_key: Vec<u8>,
    // Random token
    pub verify_token: Vec<u8>,
    // Weather the client should authenticate with the server
    pub should_authenticate: bool,
}

impl PacketDeserialize for ClientboundEncryptionRequestPacket {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        let mut index: usize = 0;
        let server_id = read_string(&data, &mut index).unwrap();
        let public_key_length = read_var_int(&data, Some(&mut index));
        let public_key = data[index..index + public_key_length as usize].to_vec();
        index += public_key_length as usize;

        let verify_token_length = read_var_int(&data, Some(&mut index));
        let verify_token = data[index..index + verify_token_length as usize].to_vec();

        let should_authenticate = read_boolean(&data, Some(&mut index));

        Ok(ClientboundEncryptionRequestPacket {
            server_id,
            public_key,
            verify_token,
            should_authenticate: should_authenticate.is_some() && should_authenticate.unwrap(),
        })
    }
}
