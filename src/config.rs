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
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence, no transit token).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_string(),
            default_transit_key: DEFAULT_TRANSIT_KEY.to_string(),
            transit_token: None,
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
