#[derive(Debug)]
pub enum OAuth2Error {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    Other(String)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResponse {
    Success {
        /// Authorization code given by the provider
        /// To be exhanged by the Client for a token
        code: String,

        /// Initial request state to be verified
        /// To prevent CSRF attack
        state: Option<String>
    },
    Error {
        /// OAuth2 error code (access_denied, ...)
        error: OAuth2Error,

        /// Readable error description
        error_description: Option<String>
    },
}