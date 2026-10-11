//! `fingerprintd` binary entry point: initialize tracing, load configuration,
//! bind the listener, and serve the router with graceful shutdown.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use fingerprintd_server::{build_router, config::Config, state::AppState};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "fingerprintd exited with error");
            ExitCode::FAILURE
        }
    }
}

/// Wire configuration, the listener, and the server together.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    tracing::info!(bind_addr = %config.bind_addr, "starting fingerprintd");

    let state = AppState::from_config(&config);

    // Compliance retention: when a window is configured, sweep the
    // fingerprint library on a timer so records age out even without identify
    // traffic. Disabled (default) leaves behaviour unchanged.
    if state.retention_ms > 0 {
        spawn_retention_sweep(state.clone(), config.retention_secs);
    }

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!(local_addr = %listener.local_addr()?, "listening");

    axum::serve(listener, build_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Spawn the background compliance retention sweep.
///
/// Every `retention_secs` (clamped to `[1s, 1h]` so a long window still reclaims
/// promptly and a short one never busy-loops), purge records older than the
/// configured window. Only called when `retention_secs > 0`; the task runs until
/// the process shuts down.
fn spawn_retention_sweep(state: AppState, retention_secs: u64) {
    let period = std::time::Duration::from_secs(retention_secs.clamp(1, 3600));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        loop {
            ticker.tick().await;
            let purged = state.matcher.purge_expired(now_ms(), state.retention_ms);
            if purged > 0 {
                tracing::info!(purged, "retention sweep purged aged records");
            }
        }
    });
}

/// Current Unix time in milliseconds, saturating to `0` before the epoch — the
/// clock the retention sweep compares record `last_seen` against.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Initialize the tracing subscriber (pretty in dev; level via `RUST_LOG`).
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

/// Resolve when the process receives Ctrl-C (SIGINT), triggering graceful shutdown.
async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %err, "failed to install Ctrl-C handler");
    }
    tracing::info!("shutdown signal received");
}
