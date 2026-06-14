mod provider;
mod engine;

use clap::Parser;
use engine::OAuth2Engine;
use std::env;
use provider::{Provider, Registry};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    provider: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    let base_redirect_uri = match env::var("BASE_REDIRECT_URI") {
        Ok(v) => v,
        Err(_) => { eprintln!("Error: BASE_REDIRECT_URI env var not set"); std::process::exit(1); }
    };

    let provider = match Provider::from_env(&args.provider) {
        Ok(p) => p,
        Err(e) => { eprintln!("Error: {}", e); std::process::exit(1); }
    };

    let mut registry = Registry::new();
    registry.register(provider);

    let provider = registry.get(&args.provider).expect("just registered");
    let engine = OAuth2Engine::new(reqwest::Client::new(), &base_redirect_uri);

    match engine.authenticate(provider).await {
        Ok(result) => {
            println!("Successfully obtained access token");
            match result.expires_in {
                Some(secs) => println!("Token expires in: {}s", secs),
                None => println!("Token does not expire"),
            }
            dbg!(result.scope);
            dbg!(result.user_info);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
