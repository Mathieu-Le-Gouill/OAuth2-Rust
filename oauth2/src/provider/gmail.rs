use super::{ProviderEndpoints, ProviderIdentity};

// ── Google (Gmail, Calendar, Meet, Docs) ──
// Confidential client: "Desktop app" type in Google Cloud Console requires a
// client_secret for token exchange. Secret is held by auth-proxy, not bundled.
pub static GMAIL_IDENTITY: ProviderIdentity = ProviderIdentity {
    name: "gmail",

    scopes: "https://mail.google.com/ https://www.googleapis.com/auth/gmail.readonly",
    uses_pkce: true,
    confidential: true
    
    //extra_auth_params: GOOGLE_OFFLINE
};
        

pub static GMAIL_ENDPOINTS: ProviderEndpoints = ProviderEndpoints {
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    fetch_url: "https://openidconnect.googleapis.com/v1/userinfo"
};
        