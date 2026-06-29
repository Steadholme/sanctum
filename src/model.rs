//! Core domain types: a stored secret version, its metadata, and a value-free history row.
//!
//! Field order/types mirror the agreed schema (db `sanctum`):
//!   secrets(path, version, ciphertext, created_at, created_by, PRIMARY KEY(path, version))
//!   secret_meta(path PRIMARY KEY, latest_version, updated_at)
//!
//! `ciphertext` is ALWAYS the `base64(nonce || AES-256-GCM(value))` blob — the plaintext value is
//! never represented in any of these structs.

/// One stored version of a secret (the `secrets` row). `ciphertext` is the sealed blob, never the
/// plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretVersion {
    /// Logical secret path (the vault key).
    pub path: String,
    /// Monotonic version number (1-based; a new put is `latest + 1`).
    pub version: i64,
    /// `base64(nonce || ciphertext+tag)` — sealed value at rest.
    pub ciphertext: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
    /// `X-Auth-Subject` of the writer (display/audit only; the vault is not per-owner scoped —
    /// every signed-in admin sees every path, as a personal vault).
    pub created_by: String,
}

/// Per-path metadata (the `secret_meta` row): the current version pointer + last-write time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMeta {
    pub path: String,
    pub latest_version: i64,
    pub updated_at: i64,
}

/// A value-free history entry (the list/version views never carry ciphertext OR plaintext).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: i64,
    pub created_at: i64,
    pub created_by: String,
}
