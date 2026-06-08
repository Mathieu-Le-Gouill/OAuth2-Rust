use super::Provider;

// ── GitHub ───────────────────────────────────────────────────────────────
// Confidential client (OAuth Apps require client_secret; no PKCE support).
pub static GITHUB: Provider = Provider {
    name: "github",
    auth_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    scopes: "repo:status,read:user",
    uses_pkce: false,
    confidential: true,

    env_client_id: "GITHUB_CLIENT_ID",
    env_client_secret: "GITHUB_CLIENT_SECRET",

    //extra_auth_params: NO_EXTRA
};