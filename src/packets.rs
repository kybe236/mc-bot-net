use std::{
    io::{self, Error, ErrorKind, Read, Write},
    sync::Arc,
};

use aes::{
    Aes128,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray},
};
use cfb8::cipher::inout::InOutBuf;
use flate2::{Compression, bufread::ZlibDecoder, write::ZlibEncoder};
use rsa::{RsaPublicKey, pkcs1v15};
use tokio::{io::AsyncReadExt, net::unix::OwnedReadHalf, sync::Mutex};

use crate::{
    client::{ConnectionState, State},
    utils::data_types::varint::{read_var_int, write_var_int},
};

#[allow(unused)]
pub trait PacketSerialize {
    fn serialize(&self, state: &ConnectionState) -> Vec<u8>;
}

#[allow(unused)]
pub trait PacketDeserialize: Sized {
    fn deserialize(data: Vec<u8>) -> Result<Self, ()>;
}

#[allow(unused)]
#[derive(Debug)]
pub enum ClientboundPacket {}

impl ClientboundPacket {
    #[allow(unused)]
    pub fn deserialize(
        packet_id: i32,
        data: Vec<u8>,
        state: &ConnectionState,
    ) -> Result<ClientboundPacket, ()> {
        println!("Unknown packet ID: {}", packet_id);
        Err(())
    }
}

#[derive(Debug)]
#[allow(unused)]
pub enum ServerboundPacket {}

impl ServerboundPacket {
    #[allow(unused)]
    pub fn serialize(&self, state: &ConnectionState) -> Vec<u8> {
        println!("Unknown packet ID: {}", 0);
        Vec::new()
    }
}

#[derive(Debug)]
#[allow(unused)]
pub enum PacketType {
    Handshake,
    Login,
    Play,
    Status,
}

#[allow(unused)]
pub fn compress(data: Vec<u8>, compress_threshold: i32) -> Result<Vec<u8>, std::io::Error> {
    const MAX_PACKET_LENGTH: i32 = 2097151; // 2^21 - 1 (maximum for a 3-byte VarInt)
    const MAX_UNCOMPRESSED_LENGTH: i32 = 8388608; // 2^23 (serverbound packet limit)

    let uncompressed_length = data.len() as i32;

    if compress_threshold < 0 {
        // Compression is disabled: Packet = [Length][Packet ID + Data]
        let mut packet = Vec::new();
        write_var_int(&mut packet, &(data.len() as i32));
        packet.append(data.clone().as_mut());
        return Ok(packet);
    }

    if compress_threshold == -1 {
        let mut result = Vec::new();
        write_var_int(&mut result, &uncompressed_length);
        result.append(&mut data.clone());

        // Check for packet size exceeding the maximum VarInt packet length
        if result.len() as i32 > MAX_PACKET_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Packet length exceeds the maximum 3-byte VarInt limit: {} > {}",
                    result.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        return Ok(result);
    }

    if uncompressed_length >= compress_threshold {
        // Compress the packet: [Packet Length][Data Length][Compressed(Packet ID + Data)]
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data)?;
        let compressed = encoder.finish()?;

        let mut packet = Vec::new();
        let mut inner = Vec::new();

        write_var_int(&mut inner, &uncompressed_length);
        inner.extend_from_slice(&compressed);

        write_var_int(&mut packet, &(inner.len() as i32));
        packet.extend(inner);

        if packet.len() > MAX_PACKET_LENGTH as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Compressed packet exceeds maximum allowed size",
            ));
        }

        Ok(packet)
    } else {
        // Below threshold: [Packet Length][Data Length = 0][Uncompressed(Packet ID + Data)]
        let mut inner = Vec::new();
        write_var_int(&mut inner, &0); // Data length = 0 (means uncompressed)
        inner.append(data.clone().as_mut());

        let mut packet = Vec::new();
        write_var_int(&mut packet, &(inner.len() as i32));
        packet.extend(inner);

        if packet.len() > MAX_PACKET_LENGTH as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Uncompressed packet with Data Length = 0 exceeds size limit",
            ));
        }

        Ok(packet)
    }
}

#[allow(unused)]
pub fn decompress(data: Vec<u8>, compress_threshold: i32) -> Result<Vec<u8>, std::io::Error> {
    if compress_threshold == -1 {
        return Ok(data);
    }

    let mut offset = 0;
    let data_length = read_var_int(&data, Some(&mut offset));

    if offset > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Invalid offset",
        ));
    }

    if data_length == 0 {
        // Packet is uncompressed, data starts after length
        Ok(data[offset..].to_vec())
    } else {
        // Compressed data starts at offset
        let compressed_data = &data[offset..];
        let mut decoder = ZlibDecoder::new(compressed_data);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data)?;
        Ok(decompressed_data)
    }
}

#[allow(unused)]
pub type Aes128CfbEnc = cfb8::Encryptor<Aes128>;
#[allow(unused)]
pub type Aes128CfbDec = cfb8::Decryptor<Aes128>;

#[allow(unused)]
pub fn encrypt(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut rng = rand::thread_rng();
    public_key
        .encrypt(&mut rng, pkcs1v15::Pkcs1v15Encrypt, data)
        .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e.to_string()))
}

#[allow(unused)]
pub fn create_cipher(key: &[u8]) -> (Aes128CfbEnc, Aes128CfbDec) {
    (
        Aes128CfbEnc::new_from_slices(key, key).unwrap(),
        Aes128CfbDec::new_from_slices(key, key).unwrap(),
    )
}

#[allow(unused)]
pub fn encrypt_packet(cipher: &mut Aes128CfbEnc, packet: &mut [u8]) {
    let (chunks, rest) = InOutBuf::from(packet).into_chunks();
    assert!(rest.is_empty());
    cipher.encrypt_blocks_inout_mut(chunks);
}

#[allow(unused)]
pub fn decrypt_packet(cipher: &mut Aes128CfbDec, packet: &mut [u8]) {
    let (chunks, rest) = InOutBuf::from(packet).into_chunks();
    assert!(rest.is_empty());
    cipher.decrypt_blocks_inout_mut(chunks);
}
#[allow(unused)]
pub async fn read_encrypted_var_int_from_stream(
    stream: &mut OwnedReadHalf,
    cipher: &mut Aes128CfbDec,
) -> Result<i32, ()> {
    let mut num_read = 0;
    let mut value = 0u32;

    loop {
        // Read a single encrypted byte from the stream
        let mut encrypted_byte = [0u8; 1];
        stream.read_exact(&mut encrypted_byte).await;

        let mut block = GenericArray::clone_from_slice(&encrypted_byte);

        cipher.decrypt_block_mut(&mut block);

        let byte = block[0];

        // Extend the value with the new byte (masking the continuation bit)
        value |= (byte as u32 & 0x7F) << (7 * num_read);
        num_read += 1;

        // If the continuation bit is not set (byte & 0x80 == 0), break
        if byte & 0x80 == 0 {
            break;
        }
    }

    Ok(value as i32)
}

#[allow(unused)]
pub async fn convert(
    mut data: Vec<u8>,
    state: &Arc<Mutex<ConnectionState>>,
) -> Result<ClientboundPacket, ()> {
    if state.lock().await.encryption_enabled {
        decrypt_packet(
            state.lock().await.decrypt_cipher.as_mut().unwrap(),
            &mut data,
        );
    }

    let res = decompress(data, state.lock().await.compression_threshold).unwrap();

    data_to_packet(res, state).await
}

#[allow(unused)]
pub async fn data_to_packet(
    data: Vec<u8>,
    state: &Arc<Mutex<ConnectionState>>,
) -> Result<ClientboundPacket, ()> {
    let mut offset = 0;
    let packet_id = read_var_int(&data, Some(&mut offset));

    // Handle the packet by its ID
    handle_packet_by_code(packet_id, data[offset..].to_vec(), state).await
}

pub async fn handle_packet_by_code(
    id: i32,
    _data: Vec<u8>,
    state: &Arc<Mutex<ConnectionState>>,
) -> Result<ClientboundPacket, ()> {
    match state.lock().await.state {
        State::Handshake => {
            let rest = id;
            println!("unsupported packet: {rest}");
        }
        State::Login => {
            let rest = id;
            println!("unsupported packet: {rest}");
        }
        State::Configuration => {
            let rest = id;
            println!("unsupported packet: {rest}");
        }
        State::Status => {
            let rest = id;
            println!("unsupported packet: {rest}");
        }
        State::Play => {
            let rest = id;
            println!("unsupported packet: {rest}");
        }
    }
    Err(())
}
