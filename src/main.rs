mod auth;
mod browser;
mod vpn;

use std::{ffi::OsString, process::ExitCode};

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Cisco AnyConnect VPN server hostname or URL
    #[arg(long)]
    server: String,

    /// Delete the authentication browser's cookies and storage before login
    #[arg(long)]
    clear_browser_data: bool,

    /// Permit an explicitly specified HTTP endpoint and HTTP authentication URLs
    #[arg(long, requires = "server")]
    allow_http_endpoint: bool,

    /// Arguments passed unchanged to OpenConnect
    #[arg(last = true, allow_hyphen_values = true)]
    openconnect_args: Vec<OsString>,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    let server = auth::server_url(&cli.server, cli.allow_http_endpoint)?;

    eprintln!("Authenticating to {server}");
    let authenticated =
        auth::authenticate(server, cli.allow_http_endpoint, cli.clear_browser_data)?;

    eprintln!("Starting OpenConnect");
    vpn::connect(authenticated, &cli.openconnect_args)
}
