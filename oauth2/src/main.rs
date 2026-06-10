mod provider;
mod client;

use clap::Parser;
use crate::provider::{ProviderConfig, PROVIDERS};
use crate::client::{PkceChallenge, CsrfToken, OAuth2Callback, OAuth2Client};
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

    // Generate pkce challenge if the provider allows it
    let pkce_challenge: Option<PkceChallenge> = maybe_generate_pkce_challenge(config.uses_pkce);

    let (code_challenge, code_verifier) = borrow_pkce_fields(pkce_challenge.as_ref());
    
    // Generate a new random Csrf token
    let state: CsrfToken = CsrfToken::new_random();

    // 1. Authorization Request
    let auth_url = client.authorization_url(
        config.scopes,
        state.as_str(),
        code_challenge,
    );

    println!("\nOpen the following URL in your browser:\n");
    println!("{auth_url}");
    println!();

    // 2. Authorization Response (code) — blocks until the browser hits the redirect URI
    let callback = OAuth2Callback::listen(redirect_uri).await
        .map_err(|e| format!("Failed to receive OAuth callback: {e}"))?;

    let code = verify_callback(callback, state.as_str())
        .map_err(|e| format!("Faield to verify the auth callback: {e}"))?;

    // 3. Token Request (code exchange)
    let token = client.exchange_code(&code.as_str(), code_verifier)
        .await
        .map_err(|e| format!("Token exchange failed: {e}"))?;

    println!("Successfully obtained access token");

    match token.expires_in {
        Some(secs) => println!("Token expires in: {}s", secs),
        None => println!("Token does not expire"),
    }

    dbg!(token.scope);

    Ok(())
}


fn maybe_generate_pkce_challenge(
    use_pkce: bool
) -> Option<PkceChallenge> {

    let pkce_challenge: Option<PkceChallenge> = if use_pkce {
        Some(PkceChallenge::generate())
    } else {
        None
    };

    pkce_challenge 
}


fn borrow_pkce_fields(
    pkce_challenge : Option<&PkceChallenge>
) -> (Option<&str>, Option<&str>) {

    let code_challenge: Option<&str> = pkce_challenge
        .as_ref()
        .map(|p| p.code_challenge.as_str());

    let code_verifier: Option<&str> = pkce_challenge
        .as_ref()
        .map(|p| p.code_verifier.as_str());

    (code_challenge, code_verifier)
}


fn verify_callback(
    callback: OAuth2Callback,
    expected_state: &str,
) -> Result<String, String> {

    match callback {
        OAuth2Callback::Success { code, state } => {
            if state.as_deref() != Some(expected_state) {
                return Err("State validation failed".into());
            }

            Ok(code)
        }
        OAuth2Callback::Error { error, .. } => {
            Err(format!("OAuth error: {:?}", error))
        }
    }
}