use webserver::config::Config;
use webserver::server::WebServer;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--generate-config" {
        println!("{}", Config::example_config());
        return Ok(());
    }

    let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("config.yaml");

    let config = match Config::load_from_file(config_path) {
        Ok(c) => {
            println!("✅ Loaded configuration from: {}", config_path);
            c
        }
        Err(e) => {
            eprintln!("❌ Failed to load config: {}", e);
            eprintln!("💡 Generate config: cargo run -- --generate-config > config.yaml");
            return Err(e);
        }
    };

    let server = WebServer::new(config)?;
    server.run().await?;

    Ok(())
}
