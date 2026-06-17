# OAuth 2.0 - Rust

Rust implementation of an OAuth 2.0 client supporting the Authorization Code flow, with or without PKCE, DPoP sender-constrained tokens, and OpenID Connect (OIDC) for multiple providers (GitHub, Gmail, Outlook).

---

## Flow Overview

```
Client                      Browser/User                  Provider
  |                               |                            |
  |── 1. Build auth URL ─────────>|                            |
  |                               |── GET /authorize ─────────>|
  |                               |<─ Redirect + code ─────────|
  |<─ 2. Receive code ────────────|                            |
  |                                                            |
  |── 3. POST /token (code) ──────────────────────────────────>|
  |   [DPoP: <proof-jwt>]                                      |
  |<─ 4. access_token + refresh_token [+ id_token] ────────────|
  |                                                            |
  |── 5. GET /userinfo (Bearer/DPoP token) ───────────────────>|
  |<─ 6. User profile ─────────────────────────────────────────|
```

---

## Step 1 - Authorization Request

The client redirects the user to the provider's authorization server.

### URLs

| Provider | Authorization URL |
|----------|-------------------|
| GitHub   | `https://github.com/login/oauth/authorize` |
| Gmail    | `https://accounts.google.com/o/oauth2/v2/auth` |
| Outlook  | `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` |

### Query Parameters

| Parameter | Required | Description |
|-----------|:--------:|-------------|
| `response_type` | ✅ | Always `code` for Authorization Code Flow |
| `client_id` | ✅ | Public identifier of the application registered with the provider |
| `redirect_uri` | ✅ | Callback URL after authorization; must exactly match the pre-registered URI |
| `scope` | Recommended | Space-separated (or `+`) list of requested permissions |
| `state` | Recommended | Randomly generated opaque value to prevent CSRF attacks |
| `code_challenge` | PKCE ✅ | Hash of the `code_verifier` (S256 method) - required if the provider enforces PKCE |
| `code_challenge_method` | PKCE ✅ | Hash method: `S256` (SHA-256, recommended) or `plain` |
| `access_type` | Google | `offline` to obtain a `refresh_token` |

### Example URL (Gmail with PKCE)

```
GET https://accounts.google.com/o/oauth2/v2/auth
  ?response_type=code
  &client_id=<GOOGLE_CLIENT_ID>
  &redirect_uri=http://localhost:8080/callback
  &scope=https://mail.google.com/+https://www.googleapis.com/auth/gmail.readonly
  &state=<random_csrf_token>
  &code_challenge=<base64url(sha256(code_verifier))>
  &code_challenge_method=S256
  &access_type=offline
```

---

## Step 2 - Authorization Response (code)

After the user grants access, the provider redirects to the `redirect_uri` with:

### Response Parameters (success)

| Parameter | Description |
|-----------|-------------|
| `code` | Short-lived authorization code (typically 10 min). To be used **only once** |
| `state` | The `state` value from the initial request - **must be verified** before proceeding |

### Example

```
GET http://localhost:8080/callback
  ?code=ghu_16C7e42F292c6912E7710c838347Ae178B4a
  &state=<random_csrf_token>
```

### Error Response

```
GET http://localhost:8080/callback
  ?error=access_denied
  &error_description=The+user+denied+access
  &state=<random_csrf_token>
```

| Field | Description |
|-------|-------------|
| `error` | OAuth error code (`access_denied`, `invalid_scope`, `server_error`, …) |
| `error_description` | Human-readable error description |

---

## Step 3 - Token Request (code exchange)

The client exchanges the `code` for tokens via a server-to-server request (never exposed to the browser).

### URLs

| Provider | Token URL |
|----------|-----------|
| GitHub   | `https://github.com/login/oauth/access_token` |
| Gmail    | `https://oauth2.googleapis.com/token` |
| Outlook  | `https://login.microsoftonline.com/common/oauth2/v2.0/token` |

### Body Parameters (`application/x-www-form-urlencoded`)

| Parameter | Required | Description |
|-----------|:--------:|-------------|
| `grant_type` | ✅ | Always `authorization_code` |
| `code` | ✅ | The code received in step 2 |
| `redirect_uri` | ✅ | Same as the one used in step 1 |
| `client_id` | ✅ | Application identifier |
| `client_secret` | Confidential client | Application secret (never expose client-side) |
| `code_verifier` | PKCE ✅ | Original value (before hashing) of the `code_challenge` sent in step 1 |

### Example (Outlook with PKCE + secret)

```http
POST https://login.microsoftonline.com/common/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=M.R3_BAY.b5fa7a24-d0e8-4c6d-bb33-5a7d7a2e1234
&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback
&client_id=<MICROSOFT_CLIENT_ID>
&client_secret=<MICROSOFT_CLIENT_SECRET>
&code_verifier=<code_verifier_original>
```

---

## Step 4 - Token Response

### JSON Response Fields

| Field | Required | Description |
|-------|:--------:|-------------|
| `access_token` | ✅ | Access token to include in API calls |
| `token_type` | ✅ | Token type - typically `Bearer` |
| `expires_in` | Recommended | Token lifetime in seconds |
| `refresh_token` | Optional | Renewal token (not issued for implicit flow or if `offline` was not requested) |
| `scope` | Optional | Granted scope - required if it differs from the requested scope |
| `id_token` | OpenID Connect | JWT containing the user's identity - issued when `openid` scope is requested |

### Example Response (Gmail)

```json
{
  "access_token": "ya29.a0AfH6SMBx...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "refresh_token": "1//0gLd...",
  "scope": "https://mail.google.com/ https://www.googleapis.com/auth/gmail.readonly"
}
```

---

## Step 5 - Userinfo Request

Optional call to retrieve the user's profile using the obtained token.

### URLs

| Provider | Userinfo URL |
|----------|--------------|
| GitHub   | `https://api.github.com/user` |
| Gmail    | `https://www.googleapis.com/oauth2/v3/userinfo` |
| Outlook  | `https://graph.microsoft.com/v1.0/me` |

### Required Header

```http
GET <userinfo_url>
Authorization: Bearer <access_token>
```

### Returned Fields (per provider)

| Provider | Identity Fields |
|----------|----------------|
| GitHub   | `email`, `login` |
| Gmail    | `email` |
| Outlook  | `mail`, `userPrincipalName` |

---

## Step 6 - Refresh Token

When the `access_token` expires, the client can obtain a new one without user interaction.

### Request

```http
POST <token_url>
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<refresh_token>
&client_id=<CLIENT_ID>
&client_secret=<CLIENT_SECRET>
```

### Response

Same as step 4. A new `refresh_token` may be issued (rotation).

---

## OIDC - OpenID Connect

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0 (RFC 6749). It standardizes how clients obtain user identity information via a signed JWT called the `id_token`.

### Enabling OIDC

Add `openid` to the `scope` parameter in the authorization request. Additional standard scopes:

| Scope | Claims returned |
|-------|----------------|
| `openid` | `sub` (subject identifier) - **required** |
| `profile` | `name`, `given_name`, `family_name`, `picture` |
| `email` | `email`, `email_verified` |

### id_token

The `id_token` is a JWT returned alongside the `access_token` in the token response. It is **signed** by the provider and must be verified before use.

```
Header.Payload.Signature
```

#### Standard Claims (payload)

| Claim | Description |
|-------|-------------|
| `iss` | Issuer URL - must match the provider's expected value |
| `sub` | Unique user identifier (stable per provider) |
| `aud` | Audience - must contain your `client_id` |
| `exp` | Expiry timestamp (Unix) |
| `iat` | Issued-at timestamp (Unix) |
| `nonce` | Echo of the `nonce` sent in the auth request - **must be verified** to prevent replay attacks |
| `email` | User's email (if `email` scope was requested) |
| `name` | User's full name (if `profile` scope was requested) |

#### Example decoded payload

```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",
  "aud": "<GOOGLE_CLIENT_ID>",
  "exp": 1750000000,
  "iat": 1749996400,
  "email": "user@gmail.com",
  "email_verified": true,
  "name": "Jane Doe"
}
```

### Discovery Endpoint

OIDC providers expose a metadata document at:

```
GET <issuer>/.well-known/openid-configuration
```

| Provider | Discovery URL |
|----------|--------------|
| Gmail    | `https://accounts.google.com/.well-known/openid-configuration` |
| Outlook  | `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` |

The document lists `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, and supported scopes/algorithms - avoiding hard-coded URLs.

### Nonce

Add a `nonce` parameter (random, unguessable value) to the authorization request:

```
&nonce=<random_value>
```

The provider echoes it in the `id_token`. **Verify** that the returned `nonce` matches the one you generated before trusting the token.

### OIDC Support per Provider

| Provider | OIDC | id_token | Discovery |
|----------|:----:|:--------:|:---------:|
| GitHub   | ❌   | ❌       | ❌        |
| Gmail    | ✅   | ✅       | ✅        |
| Outlook  | ✅   | ✅       | ✅        |

---

## DPoP - Demonstrating Proof of Possession

DPoP (RFC 9449) binds access tokens to a client-held asymmetric key pair. Even if an `access_token` is intercepted, it cannot be used without the corresponding private key. The token type becomes `DPoP` instead of `Bearer`.

### Key Pair Generation

```
Generate an asymmetric key pair (e.g. ES256 / RS256).
Keep the private key in memory; include the public key in every DPoP proof.
```

### DPoP Proof JWT

For every request that carries a DPoP-bound token, sign a compact JWT:

#### Header

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { /* public key in JWK format */ }
}
```

#### Payload

| Claim | Description |
|-------|-------------|
| `jti` | Unique identifier for this proof (UUID) - prevents replay |
| `htm` | HTTP method of the target request (e.g. `"POST"`) |
| `htu` | HTTP URI of the target request (no query string / fragment) |
| `iat` | Issued-at timestamp (Unix, within ±60 s of server time) |
| `ath` | Base64url(SHA-256(access_token)) - required when the proof accompanies an API call |

```json
{
  "jti": "e1d82f1c-2e4a-4b5c-a3d0-123456789abc",
  "htm": "POST",
  "htu": "https://oauth2.googleapis.com/token",
  "iat": 1749996400
}
```

### Token Request with DPoP

```http
POST <token_url>
Content-Type: application/x-www-form-urlencoded
DPoP: <signed-dpop-proof-jwt>

grant_type=authorization_code
&code=<code>
&redirect_uri=<redirect_uri>
&client_id=<CLIENT_ID>
&code_verifier=<code_verifier>
```

The server returns the `access_token` bound to the public key embedded in the proof, and `token_type: DPoP`.

### API Call with DPoP

```http
GET <userinfo_url>
Authorization: DPoP <access_token>
DPoP: <new-signed-proof-with-ath>
```

The `ath` claim in the new proof is `base64url(sha256(<access_token>))`.

### DPoP Flow Overview

```
Client                                    Provider
  |                                           |
  |── Generate key pair ─────────────────────>|
  |── POST /token + DPoP proof ──────────────>|
  |<── access_token (DPoP-bound) ─────────────|
  |                                           |
  |── GET /userinfo                           |
  |   Authorization: DPoP <access_token>      |
  |   DPoP: <proof with ath> ────────────────>|
  |<── User profile ──────────────────────────|
```

### DPoP Support per Provider

| Provider | DPoP |
|----------|:----:|
| GitHub   | ❌   |
| Gmail    | ✅   |
| Outlook  | ✅   |

---

## PKCE - Proof Key for Code Exchange

PKCE (RFC 7636) protects the Authorization Code flow against code interception. Required for public clients (mobile, desktop), recommended for all.

### Generation

```
code_verifier  = random base64url string (43–128 chars)
code_challenge = base64url(sha256(code_verifier))
```

| Provider | PKCE | Client secret |
|----------|:----:|:-------------:|
| GitHub   | ❌   | ✅ |
| Gmail    | ✅   | ✅ |
| Outlook  | ✅   | Optional |

---

## Scopes per Provider

### GitHub

| Scope | Access |
|-------|--------|
| `repo:status` | Commit status on repositories |
| `read:user` | Read user profile |

### Gmail (Google)

| Scope | Access |
|-------|--------|
| `https://mail.google.com/` | Full Gmail access |
| `https://www.googleapis.com/auth/gmail.readonly` | Read-only email access |

### Outlook (Microsoft)

| Scope | Access |
|-------|--------|
| `Mail.Read` | Read emails |
| `Calendars.Read` | Read calendar |
| `offline_access` | Obtain a `refresh_token` |
| `User.Read` | Read user profile |

---

## Environment Variables

| Variable | Provider |
|----------|----------|
| `GITHUB_CLIENT_ID` | GitHub |
| `GITHUB_CLIENT_SECRET` | GitHub |
| `GOOGLE_CLIENT_ID` | Gmail |
| `GOOGLE_CLIENT_SECRET` | Gmail |
| `MICROSOFT_CLIENT_ID` | Outlook |
| `MICROSOFT_CLIENT_SECRET` | Outlook |
| `REDIRECT_URI` | All providers |

Copy `.env.example` to `.env` and fill in the values.

---

## References

### OAuth 2.0 & Extensions

- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9449 - DPoP](https://datatracker.ietf.org/doc/html/rfc9449)

### OpenID Connect

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)

### Provider Documentation

- [GitHub OAuth Apps](https://docs.github.com/en/apps/oauth-apps)
- [Google Identity - OAuth 2.0](https://developers.google.com/identity/protocols/oauth2)
- [Google Identity - OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Microsoft Identity Platform - OAuth 2.0](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft Identity Platform - OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)

### Rust Libraries

- [GitHub oauth2-rs](https://github.com/ramosbugs/oauth2-rs/)
