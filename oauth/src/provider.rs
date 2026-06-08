mod github;
mod outlook;
mod gmail;

use github::GITHUB;
use outlook::OUTLOOK;
use gmail::GMAIL;
use crate::client::OAuth2Client;
use std::env;

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
    /// authorize URL. Independent of `confidential` - Slack uses PKCE AND is confidential.
    pub uses_pkce: bool,

    /// Whether this provider is a confidential client (requires a `client_secret`
    /// for token exchange). `false` means public-client / PKCE-only - no secret needed.
    /// Confidential providers route through `services/trust/oauth-proxy/` (Solution A).
    pub confidential: bool,

    /// Client identifier issued by the OAuth2 provider
    pub env_client_id: &'static str,

    /// Client secret issued by the OAuth2 provider
    pub env_client_secret: &'static str,

    /// Extra query params appended to the authorize URL (e.g. offline access).
    //pub extra_auth_params: &'static [(&'static str, &'static str)],
}

pub impl ProviderConfig {
    
    /// Build an OAuth2Client from the Provider Configuration
    /// Set the redirect URI to the env Var REDIRECT_URI value
    pub fn into_client() -> OAuth2Client {
        OAuth2Client {
            client_id: env::var(&self.env_client_id),
            client_secret: env::var(&self.env_client_secret),
            auth_url: &self.auth_url,
            token_url: &self.token_url,
            redirect_uri:  env::var(ENV_REDIRECT_URI)
        }
    }
}

pub static PROVIDERS: &[ProviderConfig] = &[
    GITHUB,
    OUTLOOK,
    GMAIL
];