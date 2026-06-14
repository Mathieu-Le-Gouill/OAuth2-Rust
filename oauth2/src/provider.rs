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

/// Represents a fully initialized OAuth provider instance used at runtime
/// Combines static provider metadata (identity and endpoints)
/// with dynamic credentials loaded from configuration or environment variables
#[derive(Debug, Clone)]
pub struct Provider {
    pub identity: &'static ProviderIdentity,
    pub endpoints: &'static ProviderEndpoints,
    pub credentials: ProviderCredentials,
}


#[derive(Debug, Clone, Copy)]
pub struct ProviderEndpoints {
    /// Provider authorization endpoint
    pub auth_url: &'static str,

    /// Provider token endpoint
    pub token_url: &'static str,

    // Provider user info API endpoint
    pub fetch_url: &'static str,
}


#[derive(Debug, Clone)]
pub struct ProviderCredentials {
    // Client identifier issued by the OAuth2 provider
    pub client_id: String,

    /// Client secret issued by the OAuth2 provider (None for public clients)
    pub client_secret: Option<String>,
}


/// OIDC-specific configuration, present only for providers that support OpenID Connect
#[derive(Debug, Clone, Copy)]
pub struct OidcConfig {
    /// Expected `iss` claim in the ID token. `None` skips the issuer check.
    pub issuer: Option<&'static str>,

    /// When `true`, issuer check uses prefix match instead of exact equality.
    /// Used for multi-tenant providers (e.g. Microsoft) where the tenant ID is
    /// embedded in the issuer URL.
    pub issuer_is_prefix: bool,

    /// JWKS endpoint for verifying ID token signatures.
    pub jwks_uri: &'static str,
}


/// Everything the OAuth flow needs to know about one provider
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

    /// Extra query params appended to the authorize URL (e.g. `access_type=offline`).
    pub extra_auth_params: &'static [(&'static str, &'static str)],

    /// OIDC configuration. `Some` if the provider supports OpenID Connect and returns
    /// an `id_token`; `None` for plain OAuth2 providers (e.g. GitHub).
    pub oidc: Option<OidcConfig>,
}

pub static NO_EXTRA: &[(&str, &str)] = &[];


pub static PROVIDERS_SPECS: &[(ProviderIdentity, ProviderEndpoints)] = &[
    (GITHUB_IDENTITY, GITHUB_ENDPOINTS),
    (OUTLOOK_IDENTITY, OUTLOOK_ENDPOINTS),
    (GMAIL_IDENTITY, GMAIL_ENDPOINTS)
];


impl Provider {

    /// Builds a `Provider` from the static provider registry and environment variables
    ///
    /// This function resolves a provider by name, then constructs a fully initialized
    /// runtime `Provider` instance by combining:
    ///
    /// - Static provider metadata (identity + endpoints)
    /// - Runtime credentials loaded from environment variables
    ///
    /// # Environment variables
    ///
    /// The following variables are expected based on the provider name:
    ///
    /// - `{PROVIDER_NAME}_CLIENT_ID` (required)
    /// - `{PROVIDER_NAME}_CLIENT_SECRET` (required only if the provider is confidential)
    ///
    /// Example for GitHub:
    /// - `GITHUB_CLIENT_ID`
    /// - `GITHUB_CLIENT_SECRET`
    ///
    /// # Parameters
    ///
    /// - `name`: The provider identifier (e.g. `"github"`, `"gmail"`, `"outlook"`)
    ///
    /// # Returns
    ///
    /// A fully initialized `Provider` ready to be used in the OAuth flow or an OAuthError
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
