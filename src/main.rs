//! Sanctum entry point: init state from env (select store, derive cipher, start audit), serve.
//!
//! Also exposes a dependency-free `sanctum healthcheck` subcommand used as the container
//! HEALTHCHECK: it GETs `http://127.0.0.1:$PORT/healthz` (port derived from `BIND_ADDR`) over a raw
//! TCP socket and exits 0 on `200`, 1 otherwise — so the image needs no curl.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Container HEALTHCHECK path — handled before any server setup, exits the process.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    let state = match sanctum::build_state_from_env().await {
        Ok(state) => state,
        Err(e) => {
            tracing::error!(error = %e, "failed to build application state");
            std::process::exit(1);
        }
    };

    let addr: SocketAddr = state
        .config
        .bind_addr
        .parse()
        .expect("invalid bind_addr in config");

    // Make the security posture visible at boot. Enforcement failing closed is a loud failure
    // (everything 401s), but an explicit SANCTUM_ENFORCE_GATEWAY_SIG=0 would otherwise downgrade
    // the vault silently.
    if state.config.enforce_gateway_signature {
        tracing::info!(
            operators = state.config.admin_subjects.len(),
            "gateway identity signature ENFORCED; secret reads deny-by-default"
        );
        if state.config.gateway_hmac_key.is_none() {
            tracing::error!(
                "GATEWAY_HMAC_KEY is not set while enforcement is on — every request will be \
                 rejected. Set it to the same key Sluice signs with."
            );
        }
        if state.config.admin_subjects.is_empty() {
            tracing::warn!(
                "SANCTUM_ADMIN_SUBJECTS is empty — nobody can manage the read ACL, and only a \
                 secret's own author can read it."
            );
        }
    } else {
        tracing::warn!(
            "gateway identity signature NOT enforced — X-Auth-Subject is trusted unverified. \
             This is intended for local runs only."
        );
    }

    let app = sanctum::app(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    tracing::info!(%addr, "Sanctum listening (secrets vault)");
    axum::serve(listener, app).await.expect("server error");
}

/// GET `/healthz` over a raw TCP socket. Returns process exit code (0 = healthy).
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8990".to_string());
    // Healthcheck always talks to the loopback regardless of the bind interface.
    let port = bind_addr.rsplit(':').next().unwrap_or("8990");
    let target = format!("127.0.0.1:{port}");

    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let status_line = buf.lines().next().unwrap_or("");
    Ok(status_line.contains("200"))
}
