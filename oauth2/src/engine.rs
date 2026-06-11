pub mod pkce_code_challenge;
pub mod crsf_token;
pub mod token_response;
pub mod auth_callback;
pub mod oauth_error;
pub mod app_config;


pub use token_response::TokenResponse;
pub use pkce_code_challenge::PkceChallenge;
pub use crsf_token::CsrfToken;
pub use auth_callback::OAuth2Callback;
pub use oauth_error::OAuthError;
pub use app_config::OAuthAppConfig;

use crate::provider::Provider;

use url::Url;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// OAuth2 Engine configuration
#[derive(Debug, Clone)]
pub struct OAuth2Engine {
    pub http: reqwest::Client,
}


impl OAuth2Engine {

    // OAuth2Client Constructor
    pub fn new(http: reqwest::Client) -> Self {

        Self {
            http: http
        }
    }


    /// Builds the OAuth2 authorization URL.
    ///
    /// The resulting URL can be used to redirect the user to the OAuth2
    /// provider's authorization page.
    ///
    /// # Parameters
    ///
    /// - `scope`: Space-separated list of requested OAuth2 scopes.
    /// - `state`: CSRF protection value that will be returned by the provider.
    /// - `use_pkce`: Optional PKCE code challenge. When provided, the
    ///   `code_challenge` and `code_challenge_method=S256` parameters
    ///   are added to the request.
    ///
    /// # Returns
    ///
    /// A fully-formed authorization URL containing the required OAuth2
    /// query parameters.
    /// 
    pub fn authorization_url(
        &self,
        app_config: &OAuthAppConfig,
        provider: &Provider,
        state: &str,
        pkce_code_challenge: Option<&str>
    ) -> String {

        let mut url = Url::parse(provider.endpoints.auth_url).expect("invalid auth_url");

        let client_id = &provider.credentials.client_id;
        let redirect_uri = app_config.redirect_uri(provider.identity.name);

        url.query_pairs_mut()
            .append_pair("client_id", client_id.as_str())
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", provider.identity.scopes)
            .append_pair("state", state);

        if let Some(code_challenge) = pkce_code_challenge {
            url.query_pairs_mut()
                .append_pair("code_challenge", code_challenge.into())
                .append_pair("code_challenge_method", "S256");
        }

        url.to_string()
    }
    

    /// Exchanges an OAuth2 authorization code for an access token.
    ///
    /// This function performs a POST request to the OAuth2 token endpoint using
    /// the authorization code flow. It optionally supports PKCE verification for
    /// enhanced security.
    ///
    /// # Parameters
    ///
    /// - `code`: The authorization code received from the OAuth2 redirect.
    /// - `pkce_verifier`: Optional PKCE code verifier used when PKCE is enabled.
    ///
    /// # Returns
    ///
    /// A `TokenResponse` containing the access token, refresh token (if provided),
    /// and other OAuth2 token metadata, or a request error if the exchange fails.
    /// ```
    pub async fn exchange_code(
        &self,
        app_config: &OAuthAppConfig,
        provider: &Provider,
        code: &str,
        pkce_verifier: Option<&str>
    ) -> Result<TokenResponse, OAuthError> {

        let client_id = &provider.credentials.client_id;
        let client_secret = &provider.credentials.client_secret;

        let redirect_uri = app_config.redirect_uri(provider.identity.name);
        let token_url = provider.endpoints.token_url;

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
        ];

        // Only include client_secret if present (confidential client)
        if let Some(secret) = client_secret {
            params.push(("client_secret", secret.as_str()));
        }

        if let Some(verifier) = pkce_verifier {
            params.push(("code_verifier", verifier));
        }

        // Send exchange request
        self.post_token_request(
            token_url,
            &params,
            |e| OAuthError::TokenExchange(e.to_string())
        ).await
    }


    /// Refreshes an OAuth2 access token using a refresh token.
    ///
    /// This function performs a POST request to the OAuth2 token endpoint using
    /// the refresh_token grant type. It optionally includes the client secret for
    /// confidential clients when required by the provider.
    ///
    /// # Parameters
    ///
    /// - `refresh_token`: The refresh token issued during the initial token exchange.
    ///
    /// # Returns
    ///
    /// A `TokenResponse` containing a new access token, and optionally a new refresh token
    /// and updated metadata, or an `OAuthError` if the request fails.
    pub async fn refresh_access_token(
        &self,
        provider: &Provider,
        refresh_token: &str
    ) -> Result<TokenResponse, OAuthError> {

        let client_id: &String = &provider.credentials.client_id;
        let client_secret: &Option<String> = &provider.credentials.client_secret;

        let token_url = provider.endpoints.token_url;

        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id.as_str()),
        ];

        if let Some(secret) = client_secret {
            params.push(("client_secret", secret.as_str()));
        }

        self.post_token_request(
            token_url,
            &params,
            |e| OAuthError::TokenRefresh(e.to_string())
        ).await
    }


    /// Retrieves the authenticated user's profile information from the OAuth2 provider.
    ///
    /// This function performs an authenticated HTTP GET request to the provider's
    /// user info endpoint using a Bearer access token. It validates the HTTP response
    /// and parses the returned JSON payload into a generic JSON value.
    ///
    /// # Parameters
    ///
    /// - `url`: The user info endpoint URL provided by the OAuth2 provider.
    /// - `access_token`: A valid OAuth2 access token used for authentication.
    ///
    /// # Returns
    ///
    /// A `serde_json::Value` containing the user's profile information,
    /// or an `OAuthError` if the request, authentication, or JSON parsing fails.
    pub async fn fetch_user_info(
        &self,
        provider: &Provider,
        access_token: &str
    ) -> Result<serde_json::Value, OAuthError> {

        let fetch_err = |e: reqwest::Error| OAuthError::FetchInfo(e.to_string());
        let fetch_url = provider.endpoints.fetch_url;

        let result = self.http
            .get(fetch_url)
            .header("Accept", "application/json")
            .header("User-Agent", USER_AGENT)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(fetch_err)?

            // Check HTTP Status
            .error_for_status()
            .map_err(fetch_err)?

            // Parse to Json
            .json()
            .await
            .map_err(fetch_err)?;

        Ok(result)
    }

    /// Executes a POST request to the OAuth2 token endpoint.
    async fn post_token_request<F>(
        &self,
        token_url: &str,
        params: &[(&str, &str)],
        map_err: F
    ) -> Result<TokenResponse, OAuthError> 
    where
    F: Fn(reqwest::Error) -> OAuthError {

        self.http
            .post(token_url)
            .header("Accept", "application/json")
            .form(params)
            .send()
            .await
            .map_err(&map_err)?

            // Check HTTP Status
            .error_for_status()
            .map_err(&map_err)?

            // Parse to Json
            .json::<TokenResponse>()
            .await
            .map_err(map_err)
    }
}