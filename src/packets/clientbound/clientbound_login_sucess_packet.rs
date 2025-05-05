use crate::{
    packets::PacketDeserialize,
    utils::data_types::{
        boolean::read_boolean, string::read_string, uuid::read_uuid, varint::read_var_int,
    },
};

#[allow(unused)]
#[derive(Debug)]
pub struct Property {
    pub name: String,
    pub value: String,
    pub signed: bool,
    pub signature: Option<String>,
}

/*
 * https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Success
 */

#[derive(Debug)]
#[allow(unused)]
pub struct ClientboundLoginSucessPacket {
    // The UUID of the player
    pub uuid: u128,
    // The username of the player
    pub username: String,
    // The number of properties
    pub number_of_properties: i32,
    // The properties of the player
    pub propertys: Vec<Property>,
}

impl PacketDeserialize for ClientboundLoginSucessPacket {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        let mut index: usize = 0;
        let uuid = read_uuid(&data, Some(&mut index));
        let username = read_string(&data, &mut index).unwrap();
        let number_of_properties = read_var_int(&data, Some(&mut index));

        let mut propertys = Vec::new();
        for _ in 0..number_of_properties {
            let name = read_string(&data, &mut index).unwrap();
            let value = read_string(&data, &mut index).unwrap();
            let is_signed = read_boolean(&data, Some(&mut index));
            let mut signature = None;
            if is_signed.is_some() && is_signed.unwrap() {
                signature = Some(read_string(&data, &mut index).unwrap().to_string());
            }

            propertys.push({
                Property {
                    name,
                    value,
                    signed: is_signed.is_some() && is_signed.unwrap(),
                    signature,
                }
            });
        }

        Ok(ClientboundLoginSucessPacket {
            uuid,
            username,
            number_of_properties,
            propertys,
        })
    }
}
