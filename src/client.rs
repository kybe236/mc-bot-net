use rand::{Rng, RngCore, distributions::Alphanumeric};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
    time::sleep,
};
use tokio_socks::tcp::Socks5Stream;

use crate::{
    config::Config,
    packets::{
        Aes128CfbDec, Aes128CfbEnc, ClientboundPacket, ServerboundPacket, compress, convert,
        create_cipher, encrypt, encrypt_packet, read_encrypted_var_int_from_stream,
        serverbound::{
            serverbound_encryption_response_packet::ServerboundEncryptionResponsePacket,
            serverbound_handshake_packet::ServerboundHandshakePacket,
            serverbound_login_acknowledged_packet::ServerboundLoginAcknowledgedPacket,
            serverbound_login_packet::ServerboundLoginPacket,
        },
    },
    utils::{cracked, data_types::varint::read_var_int_from_stream},
};

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
        *last_username = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        *last_password = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        *retries = 0;
    }

    match Socks5Stream::connect_with_password(
        proxy,
        config.addr.clone() + ":" + &config.port.to_string(),
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
    let addr = config.addr.clone() + ":" + &config.port.to_string();
    match TcpStream::connect(addr).await {
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
    let state = Arc::new(RwLock::new(ConnectionState {
        encryption_enabled: false,
        compression_threshold: -1,
        decrypt_cipher: None,
        encrypt_cipher: None,
        state: State::Handshake,
    }));

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
                game_loop(id, stream, config.clone(), state.clone()).await;
            }
            None => {
                retries += 1;
                println!("[{}] Retrying in 5 seconds... (retry #{})", id, retries);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Login,
    #[allow(unused)]
    Configuration,
    #[allow(unused)]
    Status,
    #[allow(unused)]
    Play,
    #[allow(unused)]
    Handshake,
}

#[derive(Debug)]
pub struct ConnectionState {
    #[allow(unused)]
    pub encryption_enabled: bool,
    #[allow(unused)]
    pub compression_threshold: i32,
    #[allow(unused)]
    pub decrypt_cipher: Option<Aes128CfbDec>,
    #[allow(unused)]
    pub encrypt_cipher: Option<Aes128CfbEnc>,
    #[allow(unused)]
    pub state: State,
}

pub async fn send_packet(
    packet: ServerboundPacket,
    stream: &mut TcpStream,
    state: &mut Arc<RwLock<ConnectionState>>,
) {
    println!("Sending packet: {:?}", packet);
    let mut data = packet.serialize(&state.read().await.state);
    data = compress(data, state.read().await.compression_threshold).unwrap();
    if state.read().await.encryption_enabled {
        encrypt_packet(
            state.write().await.encrypt_cipher.as_mut().unwrap(),
            &mut data,
        );
    }

    stream.write_all(&data).await.unwrap();
}

pub type SharedState = Arc<RwLock<ConnectionState>>;

async fn game_loop(id: usize, mut stream: TcpStream, config: Arc<Config>, mut state: SharedState) {
    println!("[{}] Starting game loop", id);

    let handshake = ServerboundHandshakePacket {
        next_state: 2,
        protocol_version: 765,
        server_address: config.addr.clone(),
        server_port: config.port,
    };

    send_packet(
        ServerboundPacket::Handshake(handshake),
        &mut stream,
        &mut state,
    )
    .await;

    state.write().await.state = State::Login;

    let login = ServerboundLoginPacket {
        username: format!("Player_{}", id),
        uuid: cracked::name_to_uuid(&format!("Player_{}", id)),
    };

    send_packet(ServerboundPacket::Login(login), &mut stream, &mut state).await;

    loop {
        let mut buf = [0u8; 1];
        let count = stream.peek(&mut buf).await.unwrap();
        if count == 0 {
            continue;
        }

        let packet_length = if state.read().await.encryption_enabled {
            read_encrypted_var_int_from_stream(
                &mut stream,
                state.write().await.decrypt_cipher.as_mut().unwrap(),
            )
            .await
            .unwrap()
        } else {
            println!("peeked: {:?}", buf);
            read_var_int_from_stream(&mut stream).await.unwrap()
        };

        if !(1..=1_048_576).contains(&packet_length) {
            println!("Invalid packet length: {}", packet_length);
        }

        let mut buffer = vec![0u8; packet_length as usize];
        stream.read_exact(&mut buffer).await.unwrap();

        println!("[{}] Received packet: {:?}", id, buffer);

        let packet = convert(buffer, &state).await;
        if packet.is_err() {
            println!("[{}] Failed to convert packet: {:?}", id, packet);
            continue;
        }
        println!("[{}] Converted packet: {:?}", id, packet);
        handle_packet(packet.unwrap(), &mut stream, state.clone()).await;
    }
}

async fn handle_packet(
    packet1: ClientboundPacket,
    stream: &mut TcpStream,
    mut state: Arc<RwLock<ConnectionState>>,
) {
    match packet1 {
        ClientboundPacket::EncryptionRequest(packet) => {
            println!("[Clientbound] Encryption Request: {:?}", packet);
            // Generate a random shared secret
            let mut shared_secret = vec![0u8; 16];
            rand::thread_rng().fill_bytes(&mut shared_secret);

            // Parse the DER-encoded public key
            let public_key = RsaPublicKey::from_public_key_der(&packet.public_key)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("public key error: {e}"),
                    )
                })
                .unwrap();

            let encrypted_shared_secret = encrypt(&public_key, &shared_secret).unwrap();
            let encrypted_verify_token = encrypt(&public_key, &packet.verify_token).unwrap();

            // Create the Encryption Response packet
            let response =
                ServerboundPacket::EncryptionResponse(ServerboundEncryptionResponsePacket {
                    shared_secret: encrypted_shared_secret,
                    verify_token: encrypted_verify_token,
                });

            // Send the packet to the server
            send_packet(response, stream, &mut state).await;
            println!("Sent encryption response");

            // Enable encryption
            state.write().await.encryption_enabled = true;
            let (enc_cipher, dec_cipher) = create_cipher(&shared_secret);
            state.write().await.decrypt_cipher = Some(dec_cipher);
            state.write().await.encrypt_cipher = Some(enc_cipher);

            println!("Encryption enabled");
        }
        ClientboundPacket::LoginSucess(packet) => {
            println!("[Clientbound] Login Success: {:?}", packet);
            let login_confirmation =
                ServerboundPacket::LoginAcknowledged(ServerboundLoginAcknowledgedPacket {});
            send_packet(login_confirmation, stream, &mut state).await;
            state.write().await.state = State::Play;
            println!("State changed to Play");
        }
        ClientboundPacket::SetCompression(compression_packet) => {
            println!("[Clientbound] Set Compression: {:?}", compression_packet);
            let mut state = state.write().await;
            state.compression_threshold = compression_packet.threshold;
            println!(
                "Compression threshold set to {}",
                compression_packet.threshold
            );
        }
        _ => {}
    }
}
