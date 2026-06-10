use url::Url;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};


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

    /// Converts OAuth2 error string into a strongly typed variant
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

        /// Optional state parameter used for CSRF protection
        state: Option<String>,
    },
    Error {
        /// OAuth2 error code (access_denied, ...)
        error: OAuth2Error,

        /// Human-readable error description (if provided by provider)
        error_description: Option<String>,

        /// Optional state returned by provider (if any)
        state: Option<String>,
    },
}


impl OAuth2Callback {

    /// Binds a local HTTP server on the redirect URI's port, waits for the
    /// provider to redirect the user's browser, then parses and returns the
    /// callback parameters
    pub async fn listen(redirect_uri: &str) -> Result<Self, String> {
        let url = Url::parse(redirect_uri).map_err(|e| e.to_string())?;
        let bind_addr = bind_addr_from_uri(&url);

        // Start listening for the OAuth provider redirect
        let listener = TcpListener::bind(&bind_addr).await
            .map_err(|e| format!("Failed to bind {}: {}", bind_addr, e))?;

        println!("Waiting for OAuth2 callback on {} ...", bind_addr);

        // Wait until the browser connects after authentication
        let (mut stream, _) = listener.accept().await
            .map_err(|e| format!("Failed to accept connection: {}", e))?;

        // Read the incoming HTTP request
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await
            .map_err(|e| format!("Failed to read request: {}", e))?;

        // Convert raw bytes into a UTF-8 string
        let request = std::str::from_utf8(&buf[..n])
            .map_err(|_| "Invalid UTF-8 in HTTP request")?;

        let path = extract_path(request)?;

        let full_url = format!("http://localhost{}", path);
        let parsed = Url::parse(&full_url).map_err(|e| e.to_string())?;

        // Convert query parameters into an OAuth callback result
        // (extract code, state, error, etc.)
        let callback = Self::from_query_pairs(parsed.query_pairs())
            .map_err(|e| e.to_string())?;

        let body = match callback {
            Self::Success { .. } => "Authorization successful - you may close this tab.",
            Self::Error { .. } => "Authorization failed - you may close this tab.",
        };

        // Send the response back to the browser
        stream
            .write_all(html_response(body).as_bytes())
            .await
            .ok();

        Ok(callback)
    }

    /// Parses OAuth2 redirect query parameters into a callback result
    /// Supports success (`code`) and error (`error`) responses from the provider
    fn from_query_pairs<'a>(
        pairs: impl Iterator<Item = (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)>
    ) -> Result<Self, String> {
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut error_description = None;

        for (k, v) in pairs {
            match k.as_ref() {
                "code" => code = Some(v),
                "state" => state = Some(v),
                "error" => error = Some(v),
                "error_description" => error_description = Some(v),
                _ => {}
            }
        }

        if let Some(code) = code {
            return Ok(Self::Success {
                code: code.into_owned(),
                state: state.map(|s| s.into_owned()),
            });
        }

        if let Some(error) = error {
            return Ok(Self::Error {
                error: OAuth2Error::from_str(&error),
                error_description: error_description.map(|e| e.into_owned()),
                state: state.map(|s| s.into_owned()),
            });
        }

        Err("OAuth callback missing code/error".into())
    }
}


/// Builds a TCP bind address (host:port) from a redirect URI
fn bind_addr_from_uri(uri: &Url) -> String {
    format!(
        "{}:{}",
        uri.host_str().unwrap_or("127.0.0.1"),
        uri.port().unwrap_or(8080)
    )
}

/// Extracts the request path and query from the first HTTP request line
fn extract_path(request: &str) -> Result<&str, String> {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Malformed HTTP request line".into())
}

/// Builds a minimal HTTP 200 response containing an HTML body
fn html_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}