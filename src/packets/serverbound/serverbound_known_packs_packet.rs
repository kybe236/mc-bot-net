use crate::{
    client::State,
    packets::{
        PacketSerialize,
        clientbound::clientbound_known_packs_packet::{ClientboundKnownPacksPacket, Pack},
    },
    utils::data_types::{string::write_string, varint::write_var_int},
};

#[derive(Debug)]
pub struct ServerboundKnownPacksPacket {
    pub pack_count: i32,
    pub packs: Vec<Pack>,
}

impl PacketSerialize for ServerboundKnownPacksPacket {
    fn serialize(&self, state: &State) -> Vec<u8> {
        if *state != State::Configuration {
            panic!("Known Packs packet can only be sent in the Play state");
        }
        let mut buffer = Vec::new();
        write_var_int(&mut buffer, &0x07);
        write_var_int(&mut buffer, &self.pack_count);

        for pack in &self.packs {
            write_string(&mut buffer, &pack.namespace);
            write_string(&mut buffer, &pack.id);
            write_string(&mut buffer, &pack.version);
        }

        buffer
    }
}

impl ServerboundKnownPacksPacket {
    pub fn from_clientbound(packet: ClientboundKnownPacksPacket) -> ServerboundKnownPacksPacket {
        ServerboundKnownPacksPacket {
            pack_count: packet.pack_count,
            packs: packet
                .packs
                .iter()
                .map(|pack| Pack {
                    namespace: pack.namespace.clone(),
                    id: pack.id.clone(),
                    version: pack.version.clone(),
                })
                .collect(),
        }
    }
}
