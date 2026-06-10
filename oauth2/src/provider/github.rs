use super::ProviderConfig;

// ── GitHub ───────────────────────────────────────────────────────────────
// Confidential client (OAuth Apps require client_secret; no PKCE support).
pub static GITHUB: ProviderConfig = ProviderConfig {
    name: "github",

    auth_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    fetch_url: "https://api.github.com/user",

    scopes: "repo:status,read:user",
    uses_pkce: false,
    confidential: true,

    client_id_env: "GITHUB_CLIENT_ID",
    client_secret_env: Some("GITHUB_CLIENT_SECRET"),

    //extra_auth_params: NO_EXTRA
};