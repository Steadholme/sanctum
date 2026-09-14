//! Server configuration, env-driven with working dev defaults.
//!
//! The in-memory dev path boots with NO configuration and NO database — exactly like
//! magpie/pastefire. Production overrides each value via the environment. The `MASTER_KEY` and the
//! audit/transit credentials are resolved in [`crate::build_state_from_env`], not here, so the
//! plaintext config stays free of secrets.

/// Default listen address (all interfaces, internal-only port 8990).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8990";

/// Public base URL of this service (used only for absolute links in the UI / README).
pub const DEFAULT_PUBLIC_BASE_URL: &str = "https://vault.w33d.xyz";

/// Default transit key name when a `/transit/*` request does not name one.
pub const DEFAULT_TRANSIT_KEY: &str = "default";

/// Hard cap on a secret path, in characters.
pub const MAX_PATH_CHARS: usize = 256;

/// Hard cap on a stored secret value, in characters.
pub const MAX_VALUE_CHARS: usize = 64 * 1024;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Public base URL (`PUBLIC_BASE_URL`).
    pub public_base_url: String,
    /// Default transit key name (`TRANSIT_KEY`).
    pub default_transit_key: String,
    /// Internal transit API token (`TRANSIT_TOKEN`). When set, a `Bearer` match authorizes the
    /// `/transit/*` endpoints for in-network service-to-service callers (no SSO). `None` => only
    /// the gateway-injected SSO identity authorizes transit.
    pub transit_token: Option<String>,
    /// Shared secret Sluice uses to sign the injected identity (`X-Auth-Sig`). Without it the
    /// service cannot tell a gateway-minted identity from a forged one.
    pub gateway_hmac_key: Option<String>,
    /// Subjects that may read any secret path. The vault's operators. Empty means nobody, which
    /// is deliberate: the read ACL is deny-by-default.
    pub admin_subjects: Vec<String>,
    /// Reject any request whose injected identity is unsigned. Defaults ON for the postgres
    /// store (i.e. production) and OFF for the in-memory store (local run + tests).
    pub enforce_gateway_signature: bool,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence, no transit token).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_string(),
            default_transit_key: DEFAULT_TRANSIT_KEY.to_string(),
            transit_token: None,
            gateway_hmac_key: None,
            // Local runs and the DB-free test suite have no gateway and no policy rows, so the
            // dev identity is an operator. `from_env` ALWAYS overwrites this from
            // SANCTUM_ADMIN_SUBJECTS (empty when unset), so it can never leak into production.
            admin_subjects: vec![crate::auth::DEV_SUBJECT.to_string()],
            // Local/dev runs and the DB-free test suite have no gateway in front of them.
            enforce_gateway_signature: false,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("PUBLIC_BASE_URL") {
            config.public_base_url = v.trim_end_matches('/').to_string();
        }
        if let Some(v) = env_nonempty("TRANSIT_KEY") {
            config.default_transit_key = v;
        }
        config.transit_token = env_nonempty("TRANSIT_TOKEN");
        config.gateway_hmac_key = env_nonempty("GATEWAY_HMAC_KEY");
        config.admin_subjects = env_nonempty("SANCTUM_ADMIN_SUBJECTS")
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        // Production is the postgres store. Anything else is a local run or a test.
        let is_prod = env_nonempty("SANCTUM_STORE").as_deref() == Some("postgres");
        config.enforce_gateway_signature = match env_nonempty("SANCTUM_ENFORCE_GATEWAY_SIG") {
            Some(v) => matches!(v.trim(), "1" | "true" | "TRUE" | "yes"),
            None => is_prod,
        };
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
