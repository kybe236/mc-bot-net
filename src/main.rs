use std::sync::Arc;
use tracing::{error, info};

mod client;
mod config;
mod packets;
mod utils;

#[tokio::main]
async fn main() {
    let config = Arc::new(config::load_config("config.json").await);

    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .with_thread_ids(true)
            .with_ansi(true)
            .with_level(true)
            .finish(),
    );

    info!("Starting {} clients", config.client_count);

    let mut handles = vec![];
    for id in 0..config.client_count {
        let config_clone = Arc::clone(&config);
        let handle = tokio::spawn(async move {
            client::run_client(id, config_clone).await;
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await {
            error!("Client task failed: {:?}", e);
        }
    }
}
