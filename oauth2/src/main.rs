mod provider;
mod client;

use clap::Parser;
use crate::provider::{ProviderConfig, PROVIDERS};
use crate::client::{PkceCodeChallenge, CsrfToken, OAuth2Callback, OAuth2Client};
use std::env;

#[derive(Parser)]
struct Args {
    /// Name of the provider
    #[arg(short, long)]
    provider: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let args = Args::parse();
    let redirect_uri = match env::var("REDIRECT_URI"){
        Ok(v) => v,
        Err(_) => { eprintln!("Error: REDIRECT_URI env var not set"); std::process::exit(1); }
    };

    let config = match get_provider_config(&args.provider) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = run_oauth2(config, &redirect_uri).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn get_provider_config(provider: &str) -> Result<&'static ProviderConfig, String> {
    PROVIDERS
        .iter()
        .find(|p| p.name == provider)
        .ok_or_else(|| format!("Unknown provider: {}", provider))
}


async fn run_oauth2(config: &'static ProviderConfig, redirect_uri: &str) -> Result<(), String> {

    let client: OAuth2Client = config.into_client(redirect_uri)
        .map_err(|e| format!("Failed to create client from provider config: {e}"))?;

    let (pkce_challenge, pkce_verifier) = config.uses_pkce
        .then(PkceCodeChallenge::new_random_sha256)
        .unzip();

    let state: CsrfToken = CsrfToken::new_random();

    // 1. Authorization Request
    let auth_url = client.authorization_url(
        config.scopes,
        state.as_str(),
        pkce_challenge.as_ref(),
    );

    println!("\nOpen the following URL in your browser:\n");
    println!("{auth_url}");
    println!();

    // 2. Authorization Response (code) — blocks until the browser hits the redirect URI
    let callback = OAuth2Callback::listen(redirect_uri).await
        .map_err(|e| format!("Failed to receive OAuth callback: {e}"))?;

    let (code, cb_state) = match callback {
        OAuth2Callback::Success { code, state } => (code, state),
        OAuth2Callback::Error { error, .. } => {
            return Err(format!("OAuth error: {:?}", error));
        }
    };

    if cb_state.unwrap().as_str() != state.as_str() {
        return Err("State validation failed".into());
    }



    // 3. Token Request (code exchange)
    let token = client.exchange_code(&code, pkce_verifier)
        .await
        .map_err(|e| format!("Token exchange failed: {e}"))?;

    println!("Successfully obtained access token");

    match token.expires_in {
        Some(secs) => println!("Token expires in: {}s", secs),
        None => println!("Token does not expire"),
    }

    Ok(())
}