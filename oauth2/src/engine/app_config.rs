/// OAuth application configuration.
///
/// Defines the base redirect URI used
/// to receive OAuth authorization callbacks
#[derive(Debug, Clone)]
pub struct OAuthAppConfig {
    base_redirect_uri: String,
}

impl OAuthAppConfig {
    pub fn new(redirect_uri: &str) -> Self {
        Self {
            base_redirect_uri: redirect_uri.into()
        }
    }

    /// Builds the provider-specific redirect URI
    ///
    /// The provider name is appended to the configured base redirect URI,
    /// allowing a single application to support multiple OAuth providers
    /// while exposing distinct callback routes
    pub fn redirect_uri(&self, provider: &'static str) -> String {
        format!("{}/{}", self.base_redirect_uri.trim_end_matches('/'), provider)
    }
}