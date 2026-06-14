use super::{ProviderEndpoints, ProviderIdentity, NO_EXTRA};

// ── GitHub ──
// Confidential client (OAuth Apps require client_secret; no PKCE support).
pub static GITHUB_IDENTITY: ProviderIdentity = ProviderIdentity {
    name: "github",

    scopes: "repo:status read:user",
    uses_pkce: false,
    confidential: true,
    extra_auth_params: NO_EXTRA,
    oidc: None,
};

pub static GITHUB_ENDPOINTS: ProviderEndpoints = ProviderEndpoints {
    auth_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    fetch_url: "https://api.github.com/user",
};
