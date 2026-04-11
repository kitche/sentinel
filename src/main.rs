use webserver::config::Config;
use webserver::server::WebServer;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // Accept wrapper-style invocations such as:
    //   webserver run -- --generate-config
    //   webserver run -- config.yaml
    if args.first().map(|arg| arg.as_str()) == Some("run") {
        args.remove(0);
        if args.first().map(|arg| arg.as_str()) == Some("--") {
            args.remove(0);
        }
    }

    if args.iter().any(|arg| arg == "--generate-config") {
        println!("{}", Config::example_config());
        return Ok(());
    }

    let config_path = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(|arg| arg.as_str())
        .unwrap_or("config.yaml");

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
