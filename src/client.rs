use std::{sync::Arc, time::Duration};

use rand::{Rng, distr::Alphanumeric};
use tokio::{io::AsyncReadExt, net::TcpStream, time::sleep};
use tokio_socks::tcp::Socks5Stream;

use crate::config::Config;

async fn connect_with_tor(
    config: &Config,
    retries: &mut usize,
    last_username: &mut String,
    last_password: &mut String,
) -> Option<TcpStream> {
    let proxy = config.tor_proxy.as_deref().unwrap_or("127.0.0.1:9050");
    let randomize = config.random_tor_node.unwrap_or(false);
    let reuse_limit = config.reuse_proxy_for_retries.unwrap_or(0);

    // Decide whether to reuse or generate new credentials
    if randomize && (*retries == 0 || *retries >= reuse_limit) {
        *last_username = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        *last_password = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        *retries = 0;
    }

    match Socks5Stream::connect_with_password(
        proxy,
        config.addr.clone(),
        last_username,
        last_password,
    )
    .await
    {
        Ok(stream) => Some(stream.into_inner()),
        Err(e) => {
            println!("[SOCKS5 connection failed]: {}", e);
            None
        }
    }
}

async fn connect_direct(config: &Config) -> Option<TcpStream> {
    match TcpStream::connect(&config.addr).await {
        Ok(stream) => Some(stream),
        Err(e) => {
            println!("[Direct connection failed]: {}", e);
            None
        }
    }
}

pub async fn run_client(id: usize, config: Arc<Config>) {
    let mut retries = 0;
    let mut last_username = String::new();
    let mut last_password = String::new();

    loop {
        let stream_result = if config.use_tor {
            connect_with_tor(
                &config,
                &mut retries,
                &mut last_username,
                &mut last_password,
            )
            .await
        } else {
            connect_direct(&config).await
        };

        match stream_result {
            Some(stream) => {
                retries = 0;
                game_loop(id, stream, config.clone()).await;
            }
            None => {
                retries += 1;
                println!("[{}] Retrying in 5 seconds... (retry #{})", id, retries);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn game_loop(id: usize, mut stream: TcpStream, _config: Arc<Config>) {
    println!("[{}] Starting game loop", id);

    loop {
        if let Some(packet) = read_packet(&mut stream).await {
            // Process packet here
            println!("[{}] Received packet with data: {:?}", id, packet);
        } else {
            println!("[{}] Failed to read packet.", id);
        }
    }
}

async fn read_packet(stream: &mut TcpStream) -> Option<Vec<u8>> {
    // Read the packet length (VarInt)
    let mut len_buffer = vec![0; 5]; // Maximum size for a VarInt
    let len = match stream.read_exact(&mut len_buffer).await {
        Ok(_) => {
            let mut cursor = std::io::Cursor::new(len_buffer);
            read_varint(&mut cursor).await
        }
        Err(_) => return None,
    };

    if len > 0xFF_FF_FF {
        // Validate packet length (max allowed)
        return None;
    }

    // Read the packet ID (VarInt)
    let mut id_buffer = vec![0; 5]; // Maximum size for a VarInt
    let _id_len = match stream.read_exact(&mut id_buffer).await {
        Ok(_) => {
            let mut cursor = std::io::Cursor::new(id_buffer);
            read_varint(&mut cursor).await
        }
        Err(_) => return None,
    };

    // Read the packet data (byte array)
    let mut data = vec![0; len as usize];
    if stream.read_exact(&mut data).await.is_err() {
        return None;
    }

    Some(data)
}

async fn read_varint<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> i32 {
    let mut value = 0;
    let mut bytes_read = 0;

    loop {
        let byte = reader.read_u8().await.unwrap(); // Read a single byte from the stream
        value |= ((byte & 0x7F) as i32) << (7 * bytes_read);
        if (byte & 0x80) == 0 {
            break;
        }
        bytes_read += 1;
    }
    value
}
