use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TokenResponse {

    /// The access token issued by the OAuth2 provider
    pub access_token: String,

    /// The access token type: typically the string "Bearer"
    pub token_type: String,

    /// The access token lifetime in seconds
    pub expires_in: Option<u64>,

    /// The refresh token issued by the OAuth2 provider
    /// Used to obtain a new access token after the current one expires
    pub refresh_token: Option<String>,

    /// The granted scope issued by the OAuth2 provider
    /// Required if it differs from the requested scope
    pub scope: Option<String>,

    /// The OIDC ID token returned by OIDC-capable providers (e.g. Google, Microsoft)
    /// when the `openid` scope is requested. `None` for non-OIDC providers.
    pub id_token: Option<String>,
}
