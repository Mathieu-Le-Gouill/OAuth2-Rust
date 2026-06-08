use url::Url;


#[derive(Debug, Clone, PartialEq, Eq)]
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


impl OAuth2Error {

    /// Converts OAuth2 error string into a strongly typed variant.
    fn from_str(s: &str) -> Self {
        match s {
            "invalid_request" => Self::InvalidRequest,
            "unauthorized_client" => Self::UnauthorizedClient,
            "access_denied" => Self::AccessDenied,
            "unsupported_response_type" => Self::UnsupportedResponseType,
            "invalid_scope" => Self::InvalidScope,
            "server_error" => Self::ServerError,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            other => Self::Other(other.to_string())
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuth2Callback {
    Success {
        /// Authorization code returned by the provider
        /// To be exchanged for an acess token
        code: String,

        /// Optional state parameter used for CSRF protection.
        state: Option<String>,
    },
    Error {
        /// OAuth2 error code (access_denied, ...)
        error: OAuth2Error,

        /// Human-readable error description (if provided by provider).
        error_description: Option<String>,

        /// Optional state returned by provider (if any).
        state: Option<String>,
    },
}


impl OAuth2Callback {

    /// Parses an OAuth2 redirect callback URL.
    ///
    /// This function extracts query parameters from the redirect URI
    /// and converts them into a structured OAuth2Callback.
    /// 
    pub fn from_url(url: &str) -> Result<Self, String> {
        let parsed = Url::parse(url)
            .map_err(|e| e.to_string())?;

        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        let mut error: Option<String> = None;
        let mut error_description: Option<String> = None;

        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.to_string()),
                "state" => state = Some(v.to_string()),
                "error" => error = Some(v.to_string()),
                "error_description" => error_description = Some(v.to_string()),
                _ => {}
            }
        }

        if let Some(code) = code {
            return Ok(Self::Success { code, state });
        }

        if let Some(error) = error {
            return Ok(Self::Error {
                error: OAuth2Error::from_str(&error),
                error_description,
                state,
            });
        }

        Err("Invalid OAuth2 callback: missing both code and error".into())
    }
}