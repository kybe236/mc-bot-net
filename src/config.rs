use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub use_tor: bool,
    pub tor_proxy: Option<String>,
    pub port: u16,
    pub addr: String,
    pub client_count: usize,
    pub random_tor_node: Option<bool>,
    pub reuse_proxy_for_retries: Option<usize>,
}

pub async fn load_config(path: &str) -> Config {
    let data = fs::read_to_string(path).expect("Unable to read config file");
    serde_json::from_str(&data).expect("Unable to parse config file")
}
