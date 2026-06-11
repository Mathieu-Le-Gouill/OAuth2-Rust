mod github;
mod outlook;
mod gmail;
mod registry;

pub use github::{GITHUB_IDENTITY, GITHUB_ENDPOINTS};
pub use outlook::{OUTLOOK_IDENTITY, OUTLOOK_ENDPOINTS};
pub use gmail::{GMAIL_IDENTITY, GMAIL_ENDPOINTS};
pub use registry::Registry;

use crate::engine::OAuthError;

use std::env;


#[derive(Debug, Clone)]
pub struct Provider {
    pub identity: &'static ProviderIdentity,
    pub endpoints: &'static ProviderEndpoints,
    pub credentials: ProviderCredentials,
}


#[derive(Debug, Clone, Copy)]
pub struct ProviderEndpoints {
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub fetch_url: &'static str,
}


#[derive(Debug, Clone)]
pub struct ProviderCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}


/// Everything the OAuth flow needs to know about one provider.
#[derive(Debug, Clone, Copy)]
pub struct ProviderIdentity {
    /// Provider name
    pub name: &'static str,

    /// Space- or comma-separated scope string (provider-specific separator).
    pub scopes: &'static str,

    /// Whether the provider requires PKCE (S256 code_challenge + verifier) in the
    /// authorize URL. Independent of `confidential`.
    pub uses_pkce: bool,

    /// Whether this provider is a confidential client (requires a `client_secret`
    /// for token exchange). `false` means public-client / PKCE-only - no secret needed.
    pub confidential: bool,

    // Extra query params appended to the authorize URL (e.g. offline access).
    //pub extra_auth_params: &'static [(&'static str, &'static str)],
}


pub static PROVIDERS_SPECS: &[(ProviderIdentity, ProviderEndpoints)] = &[
    (GITHUB_IDENTITY, GITHUB_ENDPOINTS), 
    (OUTLOOK_IDENTITY, OUTLOOK_ENDPOINTS),
    (GMAIL_IDENTITY, GMAIL_ENDPOINTS)
];


impl Provider {
    pub fn from_env(name: &str) -> Result<Self, OAuthError> {
        let (identity, endpoints) = PROVIDERS_SPECS
            .iter()
            .find(|(identity, _)| identity.name == name)
            .ok_or_else(|| OAuthError::UnknownProvider(name.to_string()))?;

        let client_secret = if identity.confidential {
            Some(
                env::var(format!("{}_CLIENT_SECRET", identity.name.to_uppercase()))
                    .map_err(|e| OAuthError::InvalidClientSecret(e.to_string()))?
            )
        } else {
            None
        };

        Ok(Self {
            identity: identity,
            credentials: ProviderCredentials {
                client_id: env::var(identity.name.to_uppercase() + "_CLIENT_ID")
                    .map_err(|e| OAuthError::InvalidClientID(e.to_string()))?,

                client_secret: client_secret
            },
            endpoints: endpoints
        })
    }
}