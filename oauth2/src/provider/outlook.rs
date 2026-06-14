use super::{OidcConfig, ProviderEndpoints, ProviderIdentity, NO_EXTRA};

// ── Outlook ──
// Use PKCE + client_secret when the app is a confidential client (web/server type);
// omit MICROSOFT_CLIENT_SECRET to use PKCE-only mode (public / mobile-desktop type).
pub static OUTLOOK_IDENTITY: ProviderIdentity = ProviderIdentity {
    name: "outlook",

    scopes: "openid Mail.Read Calendars.Read offline_access User.Read",
    uses_pkce: true,
    confidential: false,
    extra_auth_params: NO_EXTRA,
    oidc: Some(OidcConfig {
        // Microsoft common endpoint embeds the tenant ID in the issuer, e.g.
        // "https://login.microsoftonline.com/{tid}/v2.0" — use prefix match.
        issuer: Some("https://login.microsoftonline.com/"),
        issuer_is_prefix: true,
        jwks_uri: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    }),
};

pub static OUTLOOK_ENDPOINTS: ProviderEndpoints = ProviderEndpoints {
    auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    fetch_url: "https://graph.microsoft.com/v1.0/me",
};
