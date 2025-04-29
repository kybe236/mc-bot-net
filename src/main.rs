use std::{fs, sync::Arc, time::Duration};

use rand::{Rng, distr::Alphanumeric};
use serde::Deserialize;
use tokio::{net::TcpStream, time::sleep};
use tokio_socks::tcp::Socks5Stream;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub use_tor: bool,
    pub tor_proxy: Option<String>,
    pub addr: String,
    pub client_count: usize,
    pub random_tor_node: Option<bool>,
    pub reuse_proxy_for_retries: Option<usize>,
}

async fn load_config(path: &str) -> Config {
    let data = fs::read_to_string(path).expect("Unable to read config file");
    serde_json::from_str(&data).expect("Unable to parse config file")
}

async fn run_client(id: usize, config: Arc<Config>) {
    let mut retries = 0;
    let mut last_username = String::new();
    let mut last_password = String::new();

    loop {
        let stream_result = if config.use_tor {
            let proxy = config.tor_proxy.as_deref().unwrap_or("127.0.0.1:9050");

            let randomize = config.random_tor_node.unwrap_or(false);
            let reuse_limit = config.reuse_proxy_for_retries.unwrap_or(0);

            // Decide whether to reuse or generate new credentials
            if randomize && (retries == 0 || retries >= reuse_limit) {
                last_username = rand::rng()
                    .sample_iter(&Alphanumeric)
                    .take(8)
                    .map(char::from)
                    .collect();
                last_password = rand::rng()
                    .sample_iter(&Alphanumeric)
                    .take(8)
                    .map(char::from)
                    .collect();
                retries = 0;
            }

            match Socks5Stream::connect_with_password(
                proxy,
                config.addr.clone(),
                &last_username,
                &last_password,
            )
            .await
            {
                Ok(stream) => Some(stream.into_inner()),
                Err(e) => {
                    println!("[{}] SOCKS5 connection failed: {}", id, e);
                    None
                }
            }
        } else {
            match TcpStream::connect(&config.addr).await {
                Ok(stream) => Some(stream),
                Err(e) => {
                    println!("[{}] Direct connection failed: {}", id, e);
                    None
                }
            }
        };

        match stream_result {
            Some(_stream) => {
                println!("[{}] Connected successfully", id);
                retries = 0;
            }
            None => {
                retries += 1;
                println!("[{}] Retrying in 5 seconds... (retry #{})", id, retries);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let config = Arc::new(load_config("config.json").await);

    let mut handles = vec![];
    for id in 0..config.client_count {
        let config_clone = Arc::clone(&config);
        let handle = tokio::spawn(async move {
            run_client(id, config_clone).await;
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await {
            eprintln!("Client task failed: {:?}", e);
        }
    }
}
