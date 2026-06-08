mod token_response;


use token_response::TokenResponse;

use url::Url;
use reqwest::Client; 


/// OAuth2 client configuration
#[derive(Debug, Clone)]
pub struct OAuth2Client {
    /// Client identifier issued by the OAuth2 provider
    pub client_id: &'static str,

    /// Client secret issued by the OAuth2 provider
    pub client_secret: &'static str,
    
    /// Provider authorization endpoint
    pub auth_url: &'static str,

    /// Provider token endpoint
    pub token_url: &'static str,

    /// Registered callback URI
    pub redirect_uri: &'static str,

    /// Extra query params appended to the authorize URL (e.g. offline access).
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
        use_pkce: Option<&str>
    ) -> String {

        let mut url = Url::parse(&self.auth_url).expect("invalid auth_url")

        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", scope)
            .append_pair("state", state);

        if let Some(code_challenge) = use_pkce {
            url.query_pairs_mut()
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");
        }

        url.to_string()
    }

    /// Launch an HTTP Request to exchange an authorization code
    /// with an acess token + refresh token
    pub async fn exchange_code(
        &self,
        code: &str
    ) -> Result<TokenResponse, reqwest::Error> {
        // Create an HTTP client using reqwest
        let client = Client::new();

        let result = client
            .post(&self.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.redirect_uri),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?;

        Ok(result)
    }

}