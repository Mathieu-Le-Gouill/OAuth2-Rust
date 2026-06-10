use super::ProviderConfig;

// ── Outlook ──────────────────────────────────────────────────────────────
// Use PKCE + client_secret when the app is a confidential client (web/server type);
// omit MICROSOFT_CLIENT_SECRET to use PKCE-only mode (public / mobile-desktop type).
pub static OUTLOOK: ProviderConfig = ProviderConfig {
    name: "outlook",

    auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    fetch_url: "https://graph.microsoft.com/v1.0/me",

    scopes: "Mail.Read Calendars.Read offline_access User.Read",
    uses_pkce: true,
    confidential: false,

    client_id_env: "MICROSOFT_CLIENT_ID",
    client_secret_env: Some("MICROSOFT_CLIENT_SECRET"),

    //extra_auth_params: NO_EXTRA
};