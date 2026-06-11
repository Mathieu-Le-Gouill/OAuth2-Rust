use super::{ProviderEndpoints, ProviderIdentity};

// ── Outlook ──
// Use PKCE + client_secret when the app is a confidential client (web/server type);
// omit MICROSOFT_CLIENT_SECRET to use PKCE-only mode (public / mobile-desktop type).
pub static OUTLOOK_IDENTITY: ProviderIdentity = ProviderIdentity {
    name: "outlook",

    scopes: "Mail.Read Calendars.Read offline_access User.Read",
    uses_pkce: true,
    confidential: false

    //extra_auth_params: NO_EXTRA
};


pub static OUTLOOK_ENDPOINTS: ProviderEndpoints = ProviderEndpoints {
    auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    fetch_url: "https://graph.microsoft.com/v1.0/me",
};