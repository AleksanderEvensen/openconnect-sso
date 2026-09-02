mod auth;
mod browser;
mod vpn;

use std::{ffi::OsString, process::ExitCode};

use clap::{Parser, Subcommand};
use reqwest::Url;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(name = "__internal-browser-auth", hide = true)]
    InternalBrowserAuth {
        #[arg(value_parser = parse_url)]
        login_url: Url,

        #[arg(value_parser = parse_url)]
        final_url: Url,

        cookie_name: String,

        #[arg(long)]
        clear_browser_data: bool,
    },

    Connect {
        /// Cisco AnyConnect VPN server hostname or URL
        #[arg(value_parser = parse_server_url)]
        server: Url,

        /// Delete the authentication browser's cookies and storage before login
        #[arg(long)]
        clear_browser_data: bool,

        /// Permit an explicitly specified HTTP endpoint and HTTP authentication URLs
        #[arg(long)]
        allow_http_endpoint: bool,

        /// Arguments passed unchanged to OpenConnect
        #[arg(last = true, allow_hyphen_values = true)]
        openconnect_args: Vec<OsString>,
    },
}

fn main() -> ExitCode {
    configure_linux_webview();

    match run_cli() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli() -> anyhow::Result<u8> {
    let cli = Cli::parse();

    match cli.command {
        Commands::InternalBrowserAuth {
            login_url,
            final_url,
            cookie_name,
            clear_browser_data,
        } => {
            let token = browser::authenticate_in_process(
                login_url,
                final_url,
                &cookie_name,
                clear_browser_data,
            )?;
            println!("{token}");
            Ok(0)
        }
        Commands::Connect {
            allow_http_endpoint,
            clear_browser_data,
            openconnect_args,
            server,
        } => {
            auth::ensure_allowed_url(&server, allow_http_endpoint, "server endpoint")?;

            eprintln!("Authenticating to {server}");
            let authenticated =
                auth::authenticate(server, allow_http_endpoint, clear_browser_data)?;

            eprintln!("Starting OpenConnect");
            vpn::connect(authenticated, &openconnect_args)
        }
    }
}

fn parse_url(value: &str) -> Result<Url, String> {
    Url::parse(value).map_err(|error| error.to_string())
}

fn parse_server_url(value: &str) -> Result<Url, String> {
    let url = if value.contains("://") {
        parse_url(value)?
    } else {
        parse_url(&format!("https://{value}"))?
    };

    if url.host_str().is_none() {
        return Err("server URL must contain a hostname".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials are not allowed in the server URL".into());
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "server endpoint uses unsupported URL scheme {:?}",
            url.scheme()
        ));
    }

    Ok(url)
}

#[cfg(target_os = "linux")]
fn configure_linux_webview() {
    // WebKitGTK's DMA-BUF renderer can violate Wayland explicit-sync protocol on
    // NVIDIA drivers. Authentication pages do not benefit from GPU rendering.
    // SAFETY: This runs before argument parsing or any code that starts threads.
    unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_webview() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_command_and_openconnect_arguments() {
        let cli = Cli::try_parse_from([
            "openconnect-sso",
            "connect",
            "vpn.example.com",
            "--clear-browser-data",
            "--",
            "--no-dtls",
            "--verbose",
        ])
        .unwrap();

        let Commands::Connect {
            server,
            clear_browser_data,
            openconnect_args,
            ..
        } = cli.command
        else {
            panic!("expected connect command");
        };
        assert_eq!(server.as_str(), "https://vpn.example.com/");
        assert!(clear_browser_data);
        assert_eq!(
            openconnect_args,
            [OsString::from("--no-dtls"), OsString::from("--verbose")]
        );
    }

    #[test]
    fn rejects_server_flag() {
        assert!(
            Cli::try_parse_from(["openconnect-sso", "connect", "--server", "vpn.example.com"])
                .is_err()
        );
    }

    #[test]
    fn parses_internal_browser_command() {
        let cli = Cli::try_parse_from([
            "openconnect-sso",
            browser::CHILD_COMMAND,
            "https://login.example.com/",
            "https://vpn.example.com/done",
            "token",
            "--clear-browser-data",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Commands::InternalBrowserAuth {
                clear_browser_data: true,
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_urls_during_cli_parsing() {
        assert!(
            Cli::try_parse_from([
                "openconnect-sso",
                browser::CHILD_COMMAND,
                "not-a-url",
                "https://vpn.example.com/done",
                "token",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["openconnect-sso", "connect", "https://user@vpn.example.com"])
                .is_err()
        );
    }
}
