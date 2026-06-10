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

        let host = url.host_str().unwrap_or("127.0.0.1");
        let port = url.port().unwrap_or(8080);
        let bind_addr = format!("{}:{}", host, port);

        let listener = TcpListener::bind(&bind_addr).await
            .map_err(|e| format!("Failed to bind {}: {}", bind_addr, e))?;

        println!("Waiting for OAuth2 callback on {} ...", bind_addr);

        let (mut stream, _) = listener.accept().await
            .map_err(|e| format!("Failed to accept connection: {}", e))?;

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await
            .map_err(|e| format!("Failed to read request: {}", e))?;

        let request = std::str::from_utf8(&buf[..n])
            .map_err(|_| "Invalid UTF-8 in HTTP request")?;

        // First line: "GET /callback?code=...&state=... HTTP/1.1"
        let path_and_query = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or("Malformed HTTP request line")?;

        // Parse query params by prepending a throwaway base
        let full_url = format!("http://localhost{}", path_and_query);
        let parsed = Url::parse(&full_url).map_err(|e| e.to_string())?;

        let callback = Self::from_query_pairs(parsed.query_pairs());

        // Respond to the browser so the user sees a confirmation
        let body = match &callback {
            Ok(Self::Success { .. }) =>
                "<html><body><h2>Authorization successful - you may close this tab.</h2></body></html>",
            _ =>
                "<html><body><h2>Authorization failed - you may close this tab.</h2></body></html>",
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        );
        stream.write_all(response.as_bytes()).await.ok();

        callback
    }

    fn from_query_pairs<'a>(pairs: impl Iterator<Item = (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)>) -> Result<Self, String> {
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut error_description = None;

        for (k, v) in pairs {
            match k.as_ref() {
                "code"              => code              = Some(v.into_owned()),
                "state"             => state             = Some(v.into_owned()),
                "error"             => error             = Some(v.into_owned()),
                "error_description" => error_description = Some(v.into_owned()),
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

        Err("OAuth callback: missing both code and error parameters".into())
    }
}
