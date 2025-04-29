use crate::{
    packets::PacketDeserialize,
    utils::data_types::{
        boolean::read_boolean, string::read_string, uuid::read_uuid, varint::read_var_int,
    },
};

#[derive(Debug)]
pub struct Property {
    #[allow(unused)]
    pub name: String,
    #[allow(unused)]
    pub value: String,
    #[allow(unused)]
    pub signed: bool,
    #[allow(unused)]
    pub signature: Option<String>,
}

#[allow(unused)]
#[derive(Debug)]
pub struct ClientboundLoginSucessPacket {
    pub uuid: u128,
    pub username: String,
    pub number_of_properties: i32,
    pub propertys: Vec<Property>,
    pub strict_error_handling: bool,
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
            if is_signed {
                signature = Some(read_string(&data, &mut index).unwrap().to_string());
            }

            propertys.push({
                Property {
                    name,
                    value,
                    signed: is_signed,
                    signature,
                }
            });
        }

        let strict_error_handling = read_boolean(&data, Some(&mut index));

        Ok(ClientboundLoginSucessPacket {
            uuid,
            username,
            number_of_properties,
            propertys,
            strict_error_handling,
        })
    }
}
