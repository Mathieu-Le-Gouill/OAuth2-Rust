use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, encode,
    jwk::{AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType, Jwk},
};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::engine::{CsrfToken, OAuthError};


pub struct DpopKeyPair {
    pub private_key: EncodingKey,
    pub public_key: DecodingKey,
    pub jwk: Jwk,
}


#[derive(Debug, serde::Serialize)]
pub struct DpopClaims {
    pub htm: String,
    pub htu: String,
    pub iat: usize,
    pub jti: String,
}


/// Generates an ephemeral EC P-256 key pair for DPoP proof signing
pub fn generate_dpop_key_pair() -> Result<DpopKeyPair, OAuthError> {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    // Serialized into PKCS#8 PEM format
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| OAuthError::DPoPVerification(e.to_string()))?;
    let public_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| OAuthError::DPoPVerification(e.to_string()))?;

    // Format to jsonwebtoken EncodingKey and DecodingKey
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes())
        .map_err(|e| OAuthError::DPoPVerification(e.to_string()))?;
    let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())
        .map_err(|e| OAuthError::DPoPVerification(e.to_string()))?;

    // Extract uncompressed point coordinates for the public JWK
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed EC point always has x"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed EC point always has y"));

    let jwk = Jwk {
        common: CommonParameters::default(),
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x,
            y,
        }),
    };

    Ok(DpopKeyPair { private_key: encoding_key, public_key: decoding_key, jwk })
}


/// Creates a DPoP proof JWT for the given HTTP method and URI
pub fn create_dpop_proof(
    key_pair: &DpopKeyPair,
    http_method: &str,
    http_uri: &str,
) -> Result<String, OAuthError> {

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as usize;

    let header = Header {
        typ: Some("dpop+jwt".into()),
        alg: Algorithm::ES256,
        jwk: Some(key_pair.jwk.clone()),
        cty: None,
        jku: None,
        kid: None,
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let claims = DpopClaims {
        htm: http_method.to_uppercase(),
        htu: http_uri.into(),
        iat: now,
        jti: CsrfToken::new_random().as_str().into(),
    };

    encode(&header, &claims, &key_pair.private_key)
        .map_err(|e| OAuthError::DPoPVerification(e.to_string()))
}
