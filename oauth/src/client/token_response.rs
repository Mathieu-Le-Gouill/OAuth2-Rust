use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TokenResponse {

    /// The acess token issued by the OAuth2 provider
    pub access_token: String,

    /// The acess token type: typically the string "Bearer"
    pub token_type: String,

    /// The acess token lifetime in seconds
    pub expires_in: String,

    /// The refresh token issued by the OAuth2 provider
    /// Used to obtain a new acess token after the current one expire
    pub refresh_token: Optional<String>,

    /// The granted scope issued by the OAuth2 provider
    /// Required if it differs from the requested scope
    pub scope: Optional<String>
}