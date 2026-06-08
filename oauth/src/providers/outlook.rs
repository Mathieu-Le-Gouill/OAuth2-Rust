use super::Provider;

// ── Outlook ──────────────────────────────────────────────────────────────
// Use PKCE + client_secret when the app is a confidential client (web/server type);
// omit MICROSOFT_CLIENT_SECRET to use PKCE-only mode (public / mobile-desktop type).
pub static Outlook: Provider = Provider {
    bridge: "outlook",
    auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    scopes: "Mail.Read Calendars.Read offline_access User.Read",
    uses_pkce: true,
    confidential: false,

    env_client_id: "MICROSOFT_CLIENT_ID",
    env_client_secret: "MICROSOFT_CLIENT_SECRET",

    //extra_auth_params: NO_EXTRA
};