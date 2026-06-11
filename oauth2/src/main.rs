mod provider;
mod engine;

use clap::Parser;
use engine::{CsrfToken, OAuth2Callback, OAuth2Engine, OAuthError, PkceChallenge};
use std::env;
use provider::{Provider, Registry};

use crate::engine::OAuthAppConfig;

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


    let provider = match Provider::from_env(&args.provider) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let mut registry: Registry = Registry::new();
    registry.register(provider);

    if let Err(e) = run_oauth2(&registry, &args.provider, &redirect_uri).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}


/// Runs the full OAuth2 flow: authorization, callback handling, token exchange, and user info retrieval
async fn run_oauth2(registry: &Registry, provider_name: &str, redirect_uri: &str) -> Result<(), OAuthError> {

    let app_config: OAuthAppConfig = OAuthAppConfig::new(redirect_uri);

    let provider = registry.get(provider_name)
        .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?;

    let http = reqwest::Client::new();
    let engine = OAuth2Engine::new(http);

    // Generate pkce challenge if the provider allows it
    let pkce_challenge: Option<PkceChallenge> = maybe_generate_pkce_challenge(provider.identity.uses_pkce);

    let (code_challenge, code_verifier) = borrow_pkce_fields(pkce_challenge.as_ref());
    
    // Generate a new random Csrf token
    let state: CsrfToken = CsrfToken::new_random();

    // 1. Authorization Request
    let auth_url = engine.authorization_url(
        &app_config,
        &provider,
        state.as_str(),
        code_challenge,
    );

    println!("\nOpen the following URL in your browser:\n");
    println!("{auth_url}");
    println!();

    // 2. Authorization Response (code) — blocks until the browser hits the redirect URI
    let callback = OAuth2Callback::listen(redirect_uri)
        .await?;

    let code = verify_callback(callback, state.as_str())?;

    // 3. Token Request (code exchange)
    let token = engine.exchange_code(
        &app_config,
        &provider,
        &code.as_str(), 
        code_verifier
    ).await?;

    println!("Successfully obtained access token");

    match token.expires_in {
        Some(secs) => println!("Token expires in: {}s", secs),
        None => println!("Token does not expire"),
    }

    dbg!(token.scope);

    /*let refresh_token = token.refresh_token
        .ok_or_else(|| OAuthError::TokenRefresh("Invalid refresh token".into()))?;

    token = engine.refresh_access_token(&provider, refresh_token.as_str()).await?;

    println!("Token Successfully obtained access token");*/

    let user_info = engine.fetch_user_info(
        &provider,
        token.access_token.as_str()
    ).await?;

    dbg!(user_info);

    Ok(())
}


/// Generates a PKCE challenge if the provider supports PKCE, otherwise returns `None`
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


/// Extracts the PKCE code challenge and verifier as borrowed string slices if present
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


/// Validates the OAuth callback, ensuring state integrity and extracting the authorization code
fn verify_callback(
    callback: OAuth2Callback,
    expected_state: &str,
) -> Result<String, OAuthError> {

    match callback {
        OAuth2Callback::Success { code, state } => {
            if state.as_deref() != Some(expected_state) {
                return Err(OAuthError::StateMismatch);
            }

            Ok(code)
        }
        OAuth2Callback::Error { error, .. } => {
            Err(error)
        }
    }
}