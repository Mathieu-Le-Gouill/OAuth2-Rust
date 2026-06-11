pub struct OAuthAppConfig {
    pub base_redirect_uri: String,
}

impl OAuthAppConfig {
    pub fn new(redirect_uri: &str) -> Self {
        Self {
            base_redirect_uri: redirect_uri.into()
        }
    }

    pub fn redirect_uri(&self, provider: &'static str) -> String {
        format!("{}/{}", self.base_redirect_uri.trim_end_matches('/'), provider)
    }
}