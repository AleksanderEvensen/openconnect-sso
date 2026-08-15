use std::{
    env,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};

use crate::auth::Authenticated;

const ANYCONNECT_VERSION: &str = "4.7.00136";
const USER_AGENT: &str = "AnyConnect Linux_64 4.7.00136";

pub fn connect(auth: Authenticated, passthrough: &[OsString]) -> Result<u8> {
    let openconnect = find_executable("openconnect").context(
        "OpenConnect is not installed or not in PATH; install it before running openconnect-sso",
    )?;

    let mut command = Command::new("/usr/bin/sudo");
    command
        .arg(openconnect)
        .arg("--useragent")
        .arg(USER_AGENT)
        .arg("--version-string")
        .arg(ANYCONNECT_VERSION)
        .arg("--cookie-on-stdin")
        .arg("--servercert")
        .arg(auth.server_cert_hash)
        .args(passthrough)
        .arg(auth.server.as_str())
        .stdin(Stdio::piped());

    let mut child = command
        .spawn()
        .context("failed to start OpenConnect through sudo")?;
    let mut token = auth.session_token.into_bytes();
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open OpenConnect stdin")?;
    let write_result = stdin.write_all(&token);
    token.fill(0);
    write_result.context("failed to send the VPN session token to OpenConnect")?;
    drop(stdin);

    let status = child
        .wait()
        .context("failed while waiting for OpenConnect")?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1))
}

fn find_executable(name: &str) -> Result<PathBuf> {
    let path = env::var_os("PATH").context("PATH is not set")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if is_executable(&candidate) {
            return fs::canonicalize(&candidate)
                .with_context(|| format!("failed to resolve {}", candidate.display()));
        }
    }
    bail!("could not find {name}")
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
