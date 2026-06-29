mod api;
mod checks;
mod cli;
mod engine;
mod error;
mod expr;
mod loader;
mod model;
mod oob;
mod scan;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tracing::Level;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};
use oob::OobServer;
use scan::manager::ScanManager;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match cli.command {
        Command::Serve(args) => serve(args).await,
    }
}

async fn serve(args: cli::ServeArgs) {
    let oob_server: Option<Arc<OobServer>> = if args.oob {
        let srv = OobServer::new(args.oob_host.clone(), args.oob_port);
        if let Err(e) = srv.clone().start().await {
            eprintln!("OOB server failed to start: {e}");
            std::process::exit(1);
        }
        Some(srv)
    } else {
        None
    };

    let manager = ScanManager::new(oob_server);
    let app = api::router(manager);

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .expect("invalid listen address");

    tracing::info!(addr = %addr, "noctis daemon listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind {addr}: {e}");
            std::process::exit(1);
        });

    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| eprintln!("server error: {e}"));
}

fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    use std::io::IsTerminal;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(level.into()))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .init();
}
