pub mod pkce_code_challenge;
pub mod crsf_token;
pub mod token_response;
pub mod auth_callback;


pub use token_response::TokenResponse;
pub use pkce_code_challenge::PkceChallenge;
pub use crsf_token::CsrfToken;
pub use auth_callback::OAuth2Callback;

use url::Url;
use reqwest::Client; 


/// OAuth2 client configuration
#[derive(Debug, Clone)]
pub struct OAuth2Client {
    /// Client identifier issued by the OAuth2 provider
    pub client_id: String,

    /// Client secret issued by the OAuth2 provider (None for public clients)
    pub client_secret: Option<String>,
    
    /// Provider authorization endpoint
    pub auth_url: &'static str,

    /// Provider token endpoint
    pub token_url: &'static str,

    /// Registered callback URI
    pub redirect_uri: String,

    // Extra query params appended to the authorize URL (e.g. offline access).
    //pub extra_auth_params: &'static [(&'static str, &'static str)],
}


impl OAuth2Client {

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
        scope: &str,
        state: &str,
        pkce_code_challenge: Option<&String>
    ) -> String {

        let mut url = Url::parse(&self.auth_url).expect("invalid auth_url");

        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", scope)
            .append_pair("state", state);

        if let Some(code_challenge) = pkce_code_challenge {
            url.query_pairs_mut()
                .append_pair("code_challenge", &code_challenge)
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
        code: &str,
        pkce_verifier: Option<&String>
    ) -> Result<TokenResponse, reqwest::Error> {

        // Create an HTTP client using reqwest
        let client = Client::new();

        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
        ];

        // Only include client_secret if present (confidential client)
        if let Some(ref secret) = self.client_secret {
            form.push(("client_secret", secret.as_str()));
        }

        if let Some(ref verifier) = pkce_verifier {
            form.push(("code_verifier", verifier));
        }

        let result = client
            .post(self.token_url)
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?;

        Ok(result)
    }

}