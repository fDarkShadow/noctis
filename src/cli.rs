use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "noctis",
    about = "Vulnerability scanner — YAML-driven, Rust-native",
    version
)]
pub struct Cli {
    /// Log verbosity (-v INFO, -vv DEBUG, -vvv TRACE)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the REST API daemon
    Serve(ServeArgs),

    /// Run a one-shot scan and print findings as JSON to stdout
    Scan(ScanArgs),
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Enable the integrated OOB HTTP callback server
    #[arg(long)]
    pub oob: bool,

    /// OOB server host — must be reachable from scan targets
    #[arg(long, default_value = "127.0.0.1")]
    pub oob_host: String,

    /// OOB server listening port
    #[arg(long, default_value_t = 9090)]
    pub oob_port: u16,
}

#[derive(Parser, Debug)]
pub struct ScanArgs {
    /// Target host
    #[arg(long)]
    pub host: String,

    /// Discovered open port with its service name, format <service>:<port>.
    /// Repeat for multiple ports: --service http:80 --service https:443 --service ssh:22
    #[arg(long = "service", required = true, value_parser = parse_service)]
    pub services: Vec<crate::scan::request::DiscoveredService>,

    /// Test files or directories (glob supported)
    #[arg(long, required = true)]
    pub tests: Vec<String>,

    /// Concurrency (parallel tests)
    #[arg(long, default_value_t = 5)]
    pub concurrency: usize,
}

fn parse_service(s: &str) -> Result<crate::scan::request::DiscoveredService, String> {
    let (svc, port_str) = s.rsplit_once(':').ok_or_else(|| {
        format!("invalid service spec '{s}': expected <service>:<port>")
    })?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port '{port_str}' in '{s}'"))?;
    Ok(crate::scan::request::DiscoveredService {
        port,
        service: svc.to_string(),
        protocol: "tcp".to_string(),
    })
}
