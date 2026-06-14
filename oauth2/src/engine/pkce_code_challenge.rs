use serde::{Deserialize, Serialize};



use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};


#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Represents a PKCE (Proof Key for Code Exchange) challenge pair used in OAuth2.
///
/// This structure contains both the high-entropy `code_verifier` and the derived
/// `code_challenge`, which is sent to the authorization server to secure the
/// authorization code flow against interception attacks.
///
/// The `code_verifier` is a random string, while the `code_challenge` is its
/// SHA-256 hash encoded in base64url format.
pub struct PkceChallenge {
    pub code_verifier: String,
    pub code_challenge: String,
}


impl PkceChallenge {
    /// Returns `(code_challenge, code_verifier)` as string slices.
    pub fn borrow_fields(&self) -> (&str, &str) {
        (self.code_challenge.as_str(), self.code_verifier.as_str())
    }

    /// Generate a fresh PKCE pair with 32 bytes of entropy
    /// code_verifier  = BASE64URL(32 random bytes) - high-entropy string
    /// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let code_verifier = URL_SAFE_NO_PAD.encode(bytes);
        let digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(digest);
        Self {
            code_verifier,
            code_challenge,
        }
    }
}