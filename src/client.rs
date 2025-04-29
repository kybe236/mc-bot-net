use rand::{Rng, distr::Alphanumeric};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpStream, sync::RwLock, time::sleep};
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
    let state = Arc::new(RwLock::new(ConnectionState::default()));

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

#[derive(Debug, Default)]
pub struct ConnectionState {
    #[allow(unused)]
    pub encryption_enabled: bool,
    pub compression_threshold: Option<i32>,
}

pub type SharedState = Arc<RwLock<ConnectionState>>;

async fn game_loop(id: usize, _stream: TcpStream, _config: Arc<Config>, _state: SharedState) {
    println!("[{}] Starting game loop", id);
}
