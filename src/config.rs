use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    // Use a proxy server?
    pub use_tor: bool,
    // Adress of the proxy server
    pub tor_proxy: Option<String>,
    // Randomize credentials?
    pub random_tor_node: Option<bool>,
    // Randomize after ... retries
    pub reuse_proxy_for_retries: Option<usize>,

    // Server port
    pub port: u16,
    // Server address
    pub addr: String,

    // Amount of bots
    pub client_count: usize,
}

pub async fn load_config(path: &str) -> Config {
    let data = fs::read_to_string(path).expect("Unable to read config file");
    serde_json::from_str(&data).expect("Unable to parse config file")
}
