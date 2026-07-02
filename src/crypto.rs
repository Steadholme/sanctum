//! Authenticated encryption of secret values at rest (AES-256-GCM, RustCrypto).
//!
//! Every secret VALUE — and every transit payload — is sealed with AES-256-GCM under a key
//! DERIVED from the process `MASTER_KEY` (never the master key itself). Derivation is a
//! domain-separated SHA-256: `SHA-256("sanctum-kdf-v1\0" || context || "\0" || master)`. The
//! `context` namespaces the data-encryption keys so a stored secret can never be decrypted with a
//! transit key and vice-versa:
//!   - secret values            -> context `"secret"`
//!   - transit (named key `k`)  -> context `"transit:{k}"`
//!
//! Each seal draws a FRESH random 96-bit nonce from the OS CSPRNG; the on-the-wire/at-rest blob is
//! `base64(nonce(12) || ciphertext+tag)`. The PLAINTEXT is never stored, never logged, and never
//! leaves this module except as a deliberate decrypt. GCM's authentication tag makes tampering
//! (or a wrong key) a hard decrypt error rather than silent garbage.
//!
//! Transit ciphertext is self-describing: `sanctum:v1:{key}:{base64blob}` so a single
//! `/transit/decrypt` endpoint recovers the key name from the token (the key NAME is not secret;
//! the key MATERIAL is derived from the master key and never embedded).

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Versioned, self-describing prefix for transit tokens.
const TRANSIT_PREFIX: &str = "sanctum:v1:";
/// AES-GCM nonce length, bytes (96-bit, the GCM-recommended size).
const NONCE_LEN: usize = 12;
/// GCM authentication tag length, bytes — the minimum a valid blob can carry beyond the nonce.
const TAG_LEN: usize = 16;

/// Crypto failures. Deliberately coarse: a caller never learns *why* a decrypt failed (wrong key,
/// truncated blob, or tampering all look the same), only that the ciphertext is unusable.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encrypt failed")]
    Encrypt,
    #[error("decrypt failed")]
    Decrypt,
    #[error("malformed ciphertext")]
    Malformed,
    #[error("plaintext is not valid UTF-8")]
    Utf8,
    #[error("invalid transit key name")]
    BadKeyName,
}

/// The vault cipher. Holds ONLY the raw master-key bytes; per-context AES keys are derived on
/// demand (a cheap SHA-256) so no long-lived data-encryption key sits in memory. Cheap to share
/// behind an `Arc`.
pub struct Cipher {
    master: Vec<u8>,
}

impl Cipher {
    /// Build from the raw `MASTER_KEY` material. Any non-empty byte string works — it is run
    /// through the KDF, never used directly as an AES key.
    pub fn new(master_key: &str) -> Self {
        Cipher {
            master: master_key.as_bytes().to_vec(),
        }
    }

    /// Derive the AES-256-GCM cipher for a `context`. `new_from_slice` cannot fail here: SHA-256
    /// always yields exactly 32 bytes = an AES-256 key.
    fn cipher_for(&self, context: &str) -> Aes256Gcm {
        let mut h = Sha256::new();
        h.update(b"sanctum-kdf-v1\0");
        h.update(context.as_bytes());
        h.update(b"\0");
        h.update(&self.master);
        let key = h.finalize();
        Aes256Gcm::new_from_slice(&key).expect("sha256 digest is a valid 32-byte AES-256 key")
    }

    /// Seal `plaintext` under `context` -> `base64(nonce || ciphertext+tag)`.
    fn seal(&self, context: &str, plaintext: &[u8]) -> Result<String, CryptoError> {
        let cipher = self.cipher_for(context);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext)
            .map_err(|_| CryptoError::Encrypt)?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(B64.encode(blob))
    }

    /// Open a `base64(nonce || ciphertext+tag)` blob under `context`.
    fn open(&self, context: &str, blob_b64: &str) -> Result<Vec<u8>, CryptoError> {
        let blob = B64
            .decode(blob_b64.trim())
            .map_err(|_| CryptoError::Malformed)?;
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Malformed);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let cipher = self.cipher_for(context);
        cipher
            .decrypt(GenericArray::from_slice(nonce), ct)
            .map_err(|_| CryptoError::Decrypt)
    }

    // ---- Secret values ----------------------------------------------------

    /// Seal a secret value for storage in the `secrets.ciphertext` column.
    pub fn seal_secret(&self, plaintext: &str) -> Result<String, CryptoError> {
        self.seal("secret", plaintext.as_bytes())
    }

    /// Open a stored secret value back to its plaintext string.
    pub fn open_secret(&self, blob_b64: &str) -> Result<String, CryptoError> {
        let bytes = self.open("secret", blob_b64)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::Utf8)
    }

    // ---- Transit API ------------------------------------------------------

    /// Encrypt a transit payload under the named key -> `sanctum:v1:{key}:{base64blob}`.
    pub fn transit_encrypt(&self, key_name: &str, plaintext: &str) -> Result<String, CryptoError> {
        let key = normalize_key_name(key_name)?;
        let blob = self.seal(&format!("transit:{key}"), plaintext.as_bytes())?;
        Ok(format!("{TRANSIT_PREFIX}{key}:{blob}"))
    }

    /// Decrypt a `sanctum:v1:{key}:{blob}` transit token back to its plaintext string. The key
    /// name is recovered from the token itself.
    pub fn transit_decrypt(&self, token: &str) -> Result<String, CryptoError> {
        let rest = token
            .strip_prefix(TRANSIT_PREFIX)
            .ok_or(CryptoError::Malformed)?;
        let (key, blob) = rest.split_once(':').ok_or(CryptoError::Malformed)?;
        let key = normalize_key_name(key)?;
        let bytes = self.open(&format!("transit:{key}"), blob)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::Utf8)
    }
}

/// Validate + normalize a transit key name: 1..=64 chars of `[A-Za-z0-9._-]`. Keeping the name to
/// a safe charset means it can be embedded verbatim in the self-describing token and the KDF
/// context with no escaping.
fn normalize_key_name(name: &str) -> Result<String, CryptoError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(CryptoError::BadKeyName);
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_round_trips() {
        let c = Cipher::new("test-master-key");
        let blob = c.seal_secret("hunter2 · 秘密").unwrap();
        assert_eq!(c.open_secret(&blob).unwrap(), "hunter2 · 秘密");
    }

    #[test]
    fn ciphertext_is_not_plaintext_and_nonce_is_random() {
        let c = Cipher::new("k");
        let a = c.seal_secret("same value").unwrap();
        let b = c.seal_secret("same value").unwrap();
        // Fresh nonce per seal => identical plaintext yields different ciphertext (no ECB-style leak).
        assert_ne!(a, b);
        // The raw plaintext never appears in the stored blob.
        assert!(!a.contains("same value"));
        assert_eq!(c.open_secret(&a).unwrap(), "same value");
        assert_eq!(c.open_secret(&b).unwrap(), "same value");
    }

    #[test]
    fn wrong_master_key_cannot_decrypt() {
        let a = Cipher::new("master-A");
        let b = Cipher::new("master-B");
        let blob = a.seal_secret("top secret").unwrap();
        assert!(matches!(b.open_secret(&blob), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampering_is_detected() {
        let c = Cipher::new("k");
        let blob = c.seal_secret("integrity matters").unwrap();
        // Flip a byte in the base64 -> GCM tag check fails (Decrypt) or base64/length fails
        // (Malformed); either way it never returns wrong plaintext.
        let mut bytes = B64.decode(&blob).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = B64.encode(&bytes);
        assert!(c.open_secret(&tampered).is_err());
    }

    #[test]
    fn transit_round_trips_and_is_self_describing() {
        let c = Cipher::new("master");
        let token = c
            .transit_encrypt("default", "service-to-service payload")
            .unwrap();
        assert!(token.starts_with("sanctum:v1:default:"));
        assert_eq!(
            c.transit_decrypt(&token).unwrap(),
            "service-to-service payload"
        );
    }

    #[test]
    fn transit_keys_are_isolated() {
        let c = Cipher::new("master");
        let token = c.transit_encrypt("billing", "x").unwrap();
        // Re-labelling the token to another key name must fail authentication (different derived key).
        let forged = token.replacen("sanctum:v1:billing:", "sanctum:v1:audit:", 1);
        assert!(c.transit_decrypt(&forged).is_err());
    }

    #[test]
    fn secret_and_transit_contexts_do_not_cross() {
        let c = Cipher::new("master");
        let secret_blob = c.seal_secret("value").unwrap();
        // A raw secret blob is not a valid transit token (missing prefix) ...
        assert!(c.transit_decrypt(&secret_blob).is_err());
        // ... and a transit blob, fed to the secret opener, fails the GCM check (different context).
        let token = c.transit_encrypt("default", "value").unwrap();
        let blob = token.rsplit(':').next().unwrap();
        assert!(c.open_secret(blob).is_err());
    }

    #[test]
    fn bad_key_names_are_rejected() {
        let c = Cipher::new("master");
        assert!(matches!(
            c.transit_encrypt("has space", "x"),
            Err(CryptoError::BadKeyName)
        ));
        assert!(matches!(
            c.transit_encrypt("", "x"),
            Err(CryptoError::BadKeyName)
        ));
        assert!(matches!(
            c.transit_encrypt("path/slash", "x"),
            Err(CryptoError::BadKeyName)
        ));
    }
}
