use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation, jwk::JwkSet};
use serde::Deserialize;
use crate::provider::OidcConfig;
use super::OAuthError;


#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    nonce: Option<String>,
    // aud and exp verified in jsonwebtoken::decoding
}


/// Verifies an OIDC ID token against the provider's JWKS and returns the `sub` claim
///
/// Performs in order: algorithm guard, key resolution, signature verification,
/// then issuer / sub / nonce claim checks
pub fn verify(
    id_token: &str,
    jwks: &JwkSet,
    oidc_config: &OidcConfig,
    client_id: &str,
    expected_nonce: &str,
) -> Result<String, OAuthError> {

    let header = decode_header(id_token)
        .map_err(|e| OAuthError::JwtVerification(e.to_string()))?;

    validate_algorithm(header.alg)?;

    let key = resolve_key(jwks, &header)?;

    // To validate: exp, alg and aud
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[client_id]);

    // Verify the id token signature and validation -> return the claims
    let claims = decode::<IdTokenClaims>(id_token, &key, &validation)
        .map_err(|e| OAuthError::JwtVerification(e.to_string()))?
        .claims;

    // Manually validate iss, sub and nonce
    validate_claims(&claims, oidc_config, expected_nonce)
        .map(|()| claims.sub)
}


/// Validates the algorithm used in the JWT header is considered safe
fn validate_algorithm(alg: Algorithm) -> Result<(), OAuthError> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => Ok(()),

        alg => Err(OAuthError::JwtVerification(
            format!("rejected unsafe algorithm: {:?}", alg),
        )),
    }
}


/// Resolves the decoding key from the JWKS using the key id in the JWT header
fn resolve_key(jwks: &JwkSet, header: &Header) -> Result<DecodingKey, OAuthError> {
    let kid = header.kid.as_deref().unwrap_or("");

    let jwk = jwks.find(kid).ok_or_else(|| {
        OAuthError::JwtVerification(format!("missing kid={:?}", header.kid))
    })?;

    DecodingKey::from_jwk(jwk)
        .map_err(|e| OAuthError::JwtVerification(e.to_string()))
}


/// Validates the issuer, sub, and nonce claims of the ID token
fn validate_claims(claims: &IdTokenClaims, oidc_config: &OidcConfig, expected_nonce: &str) -> Result<(), OAuthError> {
    if let Some(expected_iss) = oidc_config.issuer {
        let ok = if oidc_config.issuer_is_prefix {
            claims.iss.starts_with(expected_iss)
        } else {
            claims.iss == expected_iss
        };

        if !ok {
            return Err(OAuthError::JwtVerification(
                format!("issuer mismatch: {}", claims.iss),
            ));
        }
    }

    if claims.sub.is_empty() {
        return Err(OAuthError::JwtVerification("empty sub".into()));
    }

    match claims.nonce.as_deref() {
        Some(n) if n == expected_nonce => Ok(()),
        _ => Err(OAuthError::NonceMismatch),
    }
}
