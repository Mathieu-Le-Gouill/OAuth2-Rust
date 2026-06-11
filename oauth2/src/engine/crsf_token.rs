use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;

/// Opaque random value tied to the authorization request
///
/// Returned unchanged by the provider in the callback, compare it against the
/// stored value to confirm the response belongs to this session
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsrfToken(String);

impl CsrfToken {

    /// Generates a cryptographically random 16-byte token, base64url-encoded
    pub fn new_random() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
