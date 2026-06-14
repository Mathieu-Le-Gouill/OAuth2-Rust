pub mod pkce_code_challenge;
pub mod crsf_token;
pub mod token_response;
pub mod auth_callback;
pub mod oauth_error;
mod app_config;
pub mod id_token;


pub use token_response::TokenResponse;
pub use pkce_code_challenge::PkceChallenge;
pub use crsf_token::CsrfToken;
pub use auth_callback::OAuth2Callback;
pub use oauth_error::OAuthError;

use app_config::OAuthAppConfig;
use crate::provider::Provider;
use jsonwebtoken::jwk::JwkSet;

use url::Url;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));


/// Result of a completed OAuth2 / OIDC authentication flow.
pub struct AuthResult {
    /// Subject claim from the OIDC ID token. `None` for non-OIDC providers (e.g. GitHub).
    pub sub: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
    pub user_info: serde_json::Value,
}


/// OAuth2 engine - stateless HTTP client bound to one base redirect URI.
#[derive(Debug, Clone)]
pub struct OAuth2Engine {
    pub http: reqwest::Client,
    app_config: OAuthAppConfig,
}


impl OAuth2Engine {

    pub fn new(http: reqwest::Client, base_redirect_uri: &str) -> Self {
        Self {
            http,
            app_config: OAuthAppConfig::new(base_redirect_uri),
        }
    }


    /// Runs the full OAuth2 / OIDC authorization code flow for a single provider:
    /// builds the auth URL, waits for the browser callback, exchanges the code,
    /// verifies the ID token (OIDC only), and fetches user info.
    pub async fn authenticate(&self, provider: &Provider) -> Result<AuthResult, OAuthError> {

        let pkce = provider.identity.uses_pkce.then(PkceChallenge::generate);
        let (code_challenge, code_verifier) = pkce.as_ref()
            .map(|p| p.borrow_fields())
            .map(|(ch, ve)| (Some(ch), Some(ve)))
            .unwrap_or((None, None));

        let state = CsrfToken::new_random();
        let nonce = provider.identity.oidc.is_some().then(CsrfToken::new_random);

        let auth_url = self.authorization_url(
            provider,
            state.as_str(),
            nonce.as_ref().map(|n| n.as_str()),
            code_challenge,
        );

        println!("\nOpen the following URL in your browser:\n{auth_url}\n");

        let redirect_uri = self.app_config.redirect_uri(provider.identity.name);
        let code = OAuth2Callback::listen(&redirect_uri).await?
            .verify_state(state.as_str())?;

        let token = self.exchange_code(provider, code.as_str(), code_verifier).await?;

        let sub = if let Some(oidc) = &provider.identity.oidc {
            let id_token = token.id_token.as_deref()
                .ok_or(OAuthError::MissingIdToken)?;
            let expected_nonce = nonce.as_ref()
                .ok_or(OAuthError::NonceMismatch)?
                .as_str();
            let sub = self.verify_id_token(provider, id_token, expected_nonce).await?;
            println!("ID token verified (signature + claims + nonce)");
            let _ = oidc;
            Some(sub)
        } else {
            None
        };

        let user_info = self.fetch_user_info(provider, token.access_token.as_str()).await?;

        Ok(AuthResult {
            sub,
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_in: token.expires_in,
            scope: token.scope,
            user_info,
        })
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
        provider: &Provider,
        state: &str,
        nonce: Option<&str>,
        pkce_code_challenge: Option<&str>
    ) -> String {

        let mut url = Url::parse(provider.endpoints.auth_url).expect("invalid auth_url");

        let client_id = &provider.credentials.client_id;
        let redirect_uri = self.app_config.redirect_uri(provider.identity.name);

        url.query_pairs_mut()
            .append_pair("client_id", client_id.as_str())
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", provider.identity.scopes)
            .append_pair("state", state);

        if let Some(code_challenge) = pkce_code_challenge {
            url.query_pairs_mut()
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");
        }

        if let Some(nonce) = nonce {
            url.query_pairs_mut()
                .append_pair("nonce", nonce);
        }

        for (key, value) in provider.identity.extra_auth_params {
            url.query_pairs_mut().append_pair(key, value);
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
    /// and other OAuth2 token metadata, or a request error if the exchange fails
    pub async fn exchange_code(
        &self,
        provider: &Provider,
        code: &str,
        pkce_verifier: Option<&str>
    ) -> Result<TokenResponse, OAuthError> {

        let client_id = &provider.credentials.client_id;
        let client_secret = &provider.credentials.client_secret;

        let redirect_uri = self.app_config.redirect_uri(provider.identity.name);
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
    /// confidential clients when required by the provider
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


    /// Retrieves the authenticated user's profile information from the OAuth2 provider
    ///
    /// This function performs an authenticated HTTP GET request to the provider's
    /// user info endpoint using a Bearer access token. It validates the HTTP response
    /// and parses the returned JSON payload into a generic JSON value
    ///
    /// # Parameters
    ///
    /// - `access_token`: A valid OAuth2 access token used for authentication
    ///
    /// # Returns
    ///
    /// A `serde_json::Value` containing the user's profile information,
    /// or an `OAuthError` if the request, authentication, or JSON parsing fails
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


    /// Verifies an OIDC ID token: fetches JWKS, validates the JWT signature,
    /// then checks iss, aud, exp, sub, and nonce claims
    ///
    /// Returns the `sub` claim (the provider's stable user identifier) on success
    pub async fn verify_id_token(
        &self,
        provider: &Provider,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<String, OAuthError> {

        let oidc = provider.identity.oidc.as_ref()
            .ok_or_else(|| OAuthError::JwtVerification("provider is not OIDC".into()))?;

        let jwks = self.fetch_jwks(oidc.jwks_uri).await?;

        id_token::verify(id_token, &jwks, oidc, &provider.credentials.client_id, expected_nonce)
    }


    /// Fetches the JSON Web Key Set (JWKS) from the provider's JWKS URI
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet, OAuthError> {
        
        let jwks = self.http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| OAuthError::JwtVerification(e.to_string()))?

            // Parse to Json
            .json()
            .await
            .map_err(|e| OAuthError::JwtVerification(e.to_string()))?;

        Ok(jwks)
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