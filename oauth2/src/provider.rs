mod github;
mod outlook;
mod gmail;

use github::GITHUB;
use outlook::OUTLOOK;
use gmail::GMAIL;
use crate::client::{OAuth2Client, OAuthError};

/// Everything the OAuth flow needs to know about one provider.
#[derive(Debug, Clone, Copy)]
pub struct ProviderConfig {
    /// Provider name
    pub name: &'static str,

    /// Provider authorization endpoint
    pub auth_url: &'static str,

    /// Provider token endpoint
    pub token_url: &'static str,

    /// Space- or comma-separated scope string (provider-specific separator).
    pub scopes: &'static str,

    /// Whether the provider requires PKCE (S256 code_challenge + verifier) in the
    /// authorize URL. Independent of `confidential`.
    pub uses_pkce: bool,

    /// Whether this provider is a confidential client (requires a `client_secret`
    /// for token exchange). `false` means public-client / PKCE-only - no secret needed.
    pub confidential: bool,

    /// Name of the env var holding the client identifier (e.g. "GITHUB_CLIENT_ID").
    pub client_id_env: &'static str,

    /// Name of the env var holding the client secret (e.g. "GITHUB_CLIENT_SECRET").
    /// `None` for public clients that never use a secret.
    pub client_secret_env: Option<&'static str>,

    // Extra query params appended to the authorize URL (e.g. offline access).
    //pub extra_auth_params: &'static [(&'static str, &'static str)],
}


impl ProviderConfig {

    /// Build an OAuth2Client from the Provider Configuration.
    /// Reads client_id and client_secret from the environment at runtime.
    pub fn into_client(&self, redirect_uri: &str) -> Result<OAuth2Client, OAuthError> {
        let client_id = std::env::var(self.client_id_env)
            .map_err(|_| OAuthError::InvalidClientID(format!("{} env var not set", self.client_id_env)))?;

        let client_secret = if self.confidential {
            let key = self.client_secret_env.ok_or_else(|| {
                OAuthError::InvalidClientSecret(format!("Confidential provider '{}' has no client_secret_env defined", self.name))
            })?;
            Some(std::env::var(key).map_err(|_| OAuthError::InvalidClientSecret(format!("{} env var not set", key)))?)
        } else {
            self.client_secret_env.and_then(|key| std::env::var(key).ok())
        };

        Ok(OAuth2Client::new(
            client_id,
            client_secret,
            self.auth_url,
            self.token_url,
            redirect_uri.to_owned(),
        ))
    }
}


pub static PROVIDERS: &[ProviderConfig] = &[
    GITHUB,
    OUTLOOK,
    GMAIL
];
