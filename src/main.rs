use std::sync::Arc;

mod client;
mod config;
mod helper;
mod packet;

#[tokio::main]
async fn main() {
    let config = Arc::new(config::load_config("config.json").await);

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
            eprintln!("Client task failed: {:?}", e);
        }
    }
}
