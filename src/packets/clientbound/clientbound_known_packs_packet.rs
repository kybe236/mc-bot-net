use crate::{
    packets::PacketDeserialize,
    utils::data_types::{string::read_string, varint::read_var_int},
};

#[derive(Debug)]
pub struct ClientboundKnownPacksPacket {
    
    pub pack_count: i32,
    
    pub packs: Vec<Pack>,
}

#[derive(Debug)]
pub struct Pack {
    
    pub namespace: String,
    
    pub id: String,
    
    pub version: String,
}

impl PacketDeserialize for ClientboundKnownPacksPacket {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        let mut index: usize = 0;
        let pack_count = read_var_int(&data, Some(&mut index));

        let mut packs = Vec::new();
        for _ in 0..pack_count {
            let namespace = read_string(&data, &mut index).unwrap();
            let id = read_string(&data, &mut index).unwrap();
            let version = read_string(&data, &mut index).unwrap();

            packs.push(Pack {
                namespace,
                id,
                version,
            });
        }

        Ok(ClientboundKnownPacksPacket { pack_count, packs })
    }
}
