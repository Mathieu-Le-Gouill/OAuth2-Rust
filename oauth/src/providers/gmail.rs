use super::Provider;

// ── Google (Gmail, Calendar, Meet, Docs) ─────────────────────────────────
// Confidential client: "Desktop app" type in Google Cloud Console requires a
// client_secret for token exchange. Secret is held by auth-proxy, not bundled.
pub static Gmail: Provider = Provider {
    name: "gmail",
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    scopes: "https://mail.google.com/ https://www.googleapis.com/auth/gmail.readonly",
    uses_pkce: true,
    confidential: true,

    env_client_id: "GOOGLE_CLIENT_ID",
    env_client_secret: "GOOGLE_CLIENT_SECRET",
    
    //extra_auth_params: GOOGLE_OFFLINE
};
        
