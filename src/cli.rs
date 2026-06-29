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
