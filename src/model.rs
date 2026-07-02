//! Core domain types: stored secret versions, metadata, lifecycle hints, read policies, and
//! value-free history rows.
//!
//! Field order/types mirror the agreed schema (db `sanctum`):
//!   secrets(path, version, ciphertext, created_at, created_by, PRIMARY KEY(path, version))
//!   secret_meta(path PRIMARY KEY, latest_version, updated_at)
//!   secret_lifecycle(path PRIMARY KEY, expires_at, rotation_due_at, rotation_state, ...)
//!   secret_read_policies(subject, path_prefix, ..., PRIMARY KEY(subject, path_prefix))
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

/// Optional lifecycle controls for a secret path. Missing rows mean "no expiry and no rotation
/// reminder"; the secret remains fully valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretLifecycle {
    pub path: String,
    pub expires_at: Option<i64>,
    pub rotation_due_at: Option<i64>,
    pub rotation_state: String,
    pub updated_at: i64,
    pub updated_by: String,
}

/// One additive read policy: `subject` may read secrets whose path is matched by `path_prefix`.
/// A special prefix `*` means every path. When no policies exist at all, legacy all-admin access
/// remains in force; once any policy exists, reads require a matching policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretReadPolicy {
    pub subject: String,
    pub path_prefix: String,
    pub created_at: i64,
    pub created_by: String,
}
