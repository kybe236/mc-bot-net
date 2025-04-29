use std::io::{Read, Write};

use flate2::bufread::ZlibDecoder;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    client::SharedState,
    helper::varint::{read_var_int, read_var_int_from_stream},
};

#[derive(Debug, Default)]
pub struct Packet {
    pub length: i32,
    pub packet_id: i32,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct CompressedPacket {
    pub length: i32,
    pub data_length: i32,
    pub packet_id: i32,
    pub data: Vec<u8>,
}

impl Packet {
    #[allow(unused)]
    pub fn new(packet_id: i32, data: Vec<u8>) -> Self {
        let length = (data.len() + 1 + 1) as i32;
        Packet {
            length,
            packet_id,
            data,
        }
    }

    #[allow(unused)]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.length.to_le_bytes());
        encoded.extend_from_slice(&self.packet_id.to_le_bytes());
        encoded.extend_from_slice(&self.data);
        encoded
    }
}

impl CompressedPacket {
    #[allow(unused)]
    pub fn new(packet_id: i32, data: Vec<u8>, data_length: i32) -> Self {
        let length = (data.len() + 1 + 1 + 1) as i32;
        CompressedPacket {
            length,
            data_length,
            packet_id,
            data,
        }
    }

    #[allow(unused)]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.length.to_le_bytes());
        encoded.extend_from_slice(&self.data_length.to_le_bytes());
        encoded.extend_from_slice(&self.packet_id.to_le_bytes());
        encoded.extend_from_slice(&self.data);
        encoded
    }
}

#[allow(unused)]
pub async fn read_packet(stream: &mut TcpStream, state: &SharedState) -> Option<Vec<u8>> {
    let length = read_var_int_from_stream(stream).await.ok()? as usize;
    if length > 0x1FFFFF {
        return None;
    }

    let mut data = vec![0u8; length];
    stream.read_exact(&mut data).await.ok()?;

    let threshold = {
        let guard = state.read().await;
        guard.compression_threshold
    };

    if let Some(thresh) = threshold {
        let mut offset = 0;
        let uncompressed_len = read_var_int(&data, Some(&mut offset));

        if uncompressed_len == 0 {
            return Some(data[offset..].to_vec());
        }

        if uncompressed_len > 0x800000 {
            return None;
        }

        let mut decoder = ZlibDecoder::new(&data[offset..]);
        let mut decompressed = Vec::with_capacity(uncompressed_len as usize);
        decoder.read_to_end(&mut decompressed).ok()?;
        Some(decompressed)
    } else {
        // No compression
        Some(data)
    }
}

#[allow(unused)]
pub async fn send_packet(stream: &mut TcpStream, packet: &Packet) {
    let encoded_packet = packet.encode();
    let length = encoded_packet.len() as i32;
    stream.write_all(&length.to_le_bytes()).await.unwrap();
    stream.write_all(&encoded_packet).await.unwrap();
}

#[allow(unused)]
pub async fn send_compressed_packet(stream: &mut TcpStream, packet: &Packet, threshold: i32) {
    if packet.length >= threshold {
        let compressed_data = compress_data(packet.data.clone()).await;
        let compressed_packet =
            CompressedPacket::new(packet.packet_id, compressed_data, packet.length);

        // Encode and send the compressed packet
        let encoded_packet = compressed_packet.encode();
        let length = encoded_packet.len() as i32;
        stream.write_all(&length.to_le_bytes()).await.unwrap();
        stream.write_all(&encoded_packet).await.unwrap();
    } else {
        send_packet(stream, packet).await;
    }
}

#[allow(unused)]
pub async fn compress_data(data: Vec<u8>) -> Vec<u8> {
    let mut compressed = Vec::new();
    let mut encoder =
        flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
    encoder.write_all(&data).unwrap();
    encoder.finish().unwrap();
    compressed
}
