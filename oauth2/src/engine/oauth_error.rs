use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OAuthError {
    #[error("callback server error: {0}")]
    CallbackServer(String),

    #[error("callback timeout: {0}")]
    CallbackTimeout(String),

    #[error("OAuth denied by user or provider: {0}")]
    OAuthDenied(String),

    #[error("state mismatch - possible CSRF attack")]
    StateMismatch,

    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    #[error("fetch info failed: {0}")]
    FetchInfo(String),

    #[error("token refresh failed: {0}")]
    TokenRefresh(String),

    #[error("unknown OAuth provider: {0}")]
    UnknownProvider(String),

    #[error("invalid client id: {0}")]
    InvalidClientID(String),

    #[error("invalid client secret: {0}")]
    InvalidClientSecret(String),

    #[error("OIDC id_token missing from token response")]
    MissingIdToken,

    #[error("nonce mismatch - possible replay attack")]
    NonceMismatch,

    #[error("JWT verification failed: {0}")]
    JwtVerification(String),
}