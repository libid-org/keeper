//! CLI entry point.

use std::{
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use clap::{
    Parser,
    Subcommand,
};
use keeper::{
    config::KeeperConfig,
    run,
};
use tracing::{
    info,
    warn,
};

/// Keeps Google JWKS roots fresh on-chain, permissionlessly.
#[derive(Parser, Debug)]
#[command(name = "keeper", version, about)]
struct Cli {
    /// Path to keeper.toml.
    #[arg(long, short, env = "KEEPER_CONFIG", default_value = "keeper.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

/// What to do.
#[derive(Subcommand, Debug)]
enum Command {
    /// Poll forever, one tick per interval.
    Run {
        /// Decide and log, but never notarize or submit.
        #[arg(long)]
        dry_run: bool,
    },
    /// One tick, then exit — nonzero when anything failed, so cron/CI can
    /// gate on it.
    Once {
        /// Decide and log, but never notarize or submit.
        #[arg(long)]
        dry_run: bool,
    },
    /// Read-only table: per network, on-chain roots vs Google's live set.
    Status,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().expect("static filter parses")),
        )
        .init();

    let cli = Cli::parse();
    let (config, networks) = match KeeperConfig::load(&cli.config) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("config error: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async {
        match cli.command {
            Command::Run { dry_run } => {
                let interval = Duration::from_secs(config.poll_interval_secs);
                info!(
                    networks = networks.len(),
                    poll_interval_secs = config.poll_interval_secs,
                    dry_run,
                    "keeper starting"
                );
                loop {
                    let outcome = run::tick(&config, &networks, dry_run).await;
                    info!(?outcome, "tick complete");
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {}
                        _ = tokio::signal::ctrl_c() => {
                            info!("keeper shutting down");
                            return ExitCode::SUCCESS;
                        }
                    }
                }
            }
            Command::Once { dry_run } => {
                let outcome = run::tick(&config, &networks, dry_run).await;
                info!(?outcome, "tick complete");
                if outcome.is_success() {
                    ExitCode::SUCCESS
                } else {
                    warn!("tick had failures");
                    ExitCode::FAILURE
                }
            }
            Command::Status => match run::status(&config, &networks).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("status error: {e:#}");
                    ExitCode::FAILURE
                }
            },
        }
    })
}
