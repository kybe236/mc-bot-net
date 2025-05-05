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
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    packets::{
        Aes128CfbDec, Aes128CfbEnc, ClientboundPacket, ServerboundPacket, compress, convert,
        create_cipher, encrypt, encrypt_packet, read_encrypted_var_int_from_stream,
        serverbound::{
            serverbound_acknowledge_finish_configuration_packet::ServerboundAcknowledgeFinishConfigurationPacket,
            serverbound_encryption_response_packet::ServerboundEncryptionResponsePacket,
            serverbound_handshake_packet::ServerboundHandshakePacket,
            serverbound_keep_alive_packet::ServerboundKeepAlivePacket,
            serverbound_known_packs_packet::ServerboundKnownPacksPacket,
            serverbound_login_acknowledged_packet::ServerboundLoginAcknowledgedPacket,
            serverbound_login_packet::ServerboundLoginPacket,
            serverbound_pong_packet::ServerboundPongPacket,
        },
    },
    utils::{cracked, data_types::varint::read_var_int_from_stream},
};

/*
 * This will connect to the addr and port via TcpStream
 * wich will get routed through proxy and random passwords if random_tor_node is set
 * !TODO better naming
 * also has a reuse_limit incase theres a check where you need to reconnect
 * !TODO add redirect delay
*/
async fn connect_with_tor(
    config: &Config,
    retries: &mut usize,
    last_username: &mut String,
    last_password: &mut String,
) -> Option<TcpStream> {
    // Defaults to localhost:9050 if not specified
    let proxy = config.tor_proxy.as_deref().unwrap_or("127.0.0.1:9050");
    // By default dont randomize proxy credentials
    let randomize = config.random_tor_node.unwrap_or(false);
    // By default reuse the proxy for 0 retries
    let reuse_limit = config.reuse_proxy_for_retries.unwrap_or(0);

    // If randomize is true and the retries are equal or greater to the reuse_limit change username and password
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
            error!("[SOCKS5 connection failed]: {}", e);
            None
        }
    }
}

/*
 * Connects to the configs addr and port via a tokio TcpStream
 * Returns None when failed
*/
async fn connect_direct(config: &Config) -> Option<TcpStream> {
    let addr = config.addr.clone() + ":" + &config.port.to_string();
    match TcpStream::connect(addr).await {
        Ok(stream) => Some(stream),
        Err(e) => {
            error!("[Direct connection failed]: {}", e);
            None
        }
    }
}

/*
 * This is going to start the main game loop after joining the server
 * !TODO exit when disconnected
 */
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
        disconnected: false,
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
                warn!("[{}] Retrying in 5 seconds... (retry #{})", id, retries);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Login,
    Configuration,
    #[allow(unused)]
    Status,
    Play,
    Handshake,
}

#[derive(Debug)]
pub struct ConnectionState {
    pub encryption_enabled: bool,
    pub compression_threshold: i32,
    pub decrypt_cipher: Option<Aes128CfbDec>,
    pub encrypt_cipher: Option<Aes128CfbEnc>,
    pub state: State,
    pub disconnected: bool,
}

/*
 * This is going to send a packet to the server using state to manage encryption and compression
 */
pub async fn send_packet(
    packet: ServerboundPacket,
    stream: &mut TcpStream,
    state: &mut Arc<RwLock<ConnectionState>>,
) {
    debug!("Sending packet: {:?}", packet);
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

/*
 * This is the actuall game loop
 */
async fn game_loop(id: usize, mut stream: TcpStream, config: Arc<Config>, mut state: SharedState) {
    info!("[{}] Starting game loop", id);

    let handshake = ServerboundHandshakePacket {
        next_state: 2,
        protocol_version: 770,
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
        username: format!("kybe236-{}", id),
        uuid: cracked::name_to_uuid(&format!("kybe236-{}", id)),
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
            debug!("peeked: {:?}", buf);
            read_var_int_from_stream(&mut stream).await.unwrap()
        };

        if !(1..=1_048_576).contains(&packet_length) {
            error!("Invalid packet length: {}", packet_length);
        }

        let mut buffer = vec![0u8; packet_length as usize];
        stream.read_exact(&mut buffer).await.unwrap();

        debug!("[{}] Received packet: {:?}", id, buffer);

        let packet = convert(buffer, &state).await;
        if packet.is_err() {
            error!("[{}] Failed to convert packet: {:?}", id, packet);
            continue;
        }
        debug!("[{}] Converted packet: {:?}", id, packet);
        handle_packet(packet.unwrap(), &mut stream, state.clone()).await;
    }
}

/*
 * This implements the behaivour when getting certain packets
 */
async fn handle_packet(
    packet1: ClientboundPacket,
    stream: &mut TcpStream,
    mut state: Arc<RwLock<ConnectionState>>,
) {
    match packet1 {
        ClientboundPacket::EncryptionRequest(packet) => {
            debug!("[Clientbound] Encryption Request: {:?}", packet);

            if packet.should_authenticate {
                state.write().await.disconnected = true;
                error!("Server requested authentication, but this client does not support it.");
                return;
            }

            let mut shared_secret = vec![0u8; 16];
            rand::thread_rng().fill_bytes(&mut shared_secret);

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

            let response =
                ServerboundPacket::EncryptionResponse(ServerboundEncryptionResponsePacket {
                    shared_secret: encrypted_shared_secret,
                    verify_token: encrypted_verify_token,
                });

            send_packet(response, stream, &mut state).await;
            debug!("Sent encryption response");

            // Enable encryption
            state.write().await.encryption_enabled = true;
            let (enc_cipher, dec_cipher) = create_cipher(&shared_secret);
            state.write().await.decrypt_cipher = Some(dec_cipher);
            state.write().await.encrypt_cipher = Some(enc_cipher);

            debug!("Encryption enabled");
        }
        ClientboundPacket::LoginSucess(packet) => {
            debug!("[Clientbound] Login Success: {:?}", packet);
            let login_confirmation =
                ServerboundPacket::LoginAcknowledged(ServerboundLoginAcknowledgedPacket {});
            send_packet(login_confirmation, stream, &mut state).await;
            state.write().await.state = State::Configuration;
            debug!("State changed to Play");
        }
        ClientboundPacket::SetCompression(compression_packet) => {
            debug!("[Clientbound] Set Compression: {:?}", compression_packet);
            let mut state = state.write().await;
            state.compression_threshold = compression_packet.threshold;
            debug!(
                "Compression threshold set to {}",
                compression_packet.threshold
            );
        }
        ClientboundPacket::FinishConfiguration(packet) => {
            debug!("[Clientbound] Finish Configuration: {:?}", packet);
            state.write().await.state = State::Play;
            debug!("State changed to Play");
            let acknowledge_packet = ServerboundPacket::AcknowledgeFinishConfiguration(
                ServerboundAcknowledgeFinishConfigurationPacket {},
            );
            send_packet(acknowledge_packet, stream, &mut state).await;
        }
        ClientboundPacket::KeepAlive(packet) => {
            debug!("[Clientbound] Keep Alive: {:?}", packet);
            let keep_alive_packet = ServerboundPacket::KeepAlive(ServerboundKeepAlivePacket {
                keep_alive_id: packet.keep_alive_id,
            });
            send_packet(keep_alive_packet, stream, &mut state).await;
        }
        // !TODO store packs
        ClientboundPacket::KnownPacks(packet) => {
            debug!("[Clientbound] Known Packs: {:?}", packet);
            let serverbound_packet = ServerboundKnownPacksPacket::from_clientbound(packet);
            send_packet(
                ServerboundPacket::KnownPacks(serverbound_packet),
                stream,
                &mut state,
            )
            .await;
        }
        ClientboundPacket::Ping(packet) => {
            debug!("[Clientbound] Ping: {:?}", packet);
            let pong_packet = ServerboundPacket::Pong(ServerboundPongPacket {
                payload: packet.payload,
            });
            send_packet(pong_packet, stream, &mut state).await;
        }
        ClientboundPacket::Disconnect(packet) => {
            debug!("[Clientbound] Disconnect: {:?}", packet);
            state.write().await.disconnected = true;
            error!("Disconnected from server: {}", packet.reason);
        }
    }
}
