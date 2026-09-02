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

    let mut command = elevated_command(&openconnect)?;
    command
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
        .context("failed to start OpenConnect with elevated privileges")?;
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

#[cfg(unix)]
fn elevated_command(openconnect: &Path) -> Result<Command> {
    let escalator = find_executable("sudo")
        .or_else(|_| find_executable("doas"))
        .context("neither sudo nor doas is installed or in PATH")?;
    let mut command = Command::new(escalator);
    command.arg(openconnect);
    Ok(command)
}

#[cfg(windows)]
fn elevated_command(openconnect: &Path) -> Result<Command> {
    anyhow::ensure!(
        is_elevated(),
        "OpenConnect requires Administrator privileges; restart this terminal as Administrator"
    );
    Ok(Command::new(openconnect))
}

fn find_executable(name: &str) -> Result<PathBuf> {
    let path = env::var_os("PATH").context("PATH is not set")?;
    for directory in env::split_paths(&path) {
        for candidate in executable_candidates(&directory, name) {
            if is_executable(&candidate) {
                return fs::canonicalize(&candidate)
                    .with_context(|| format!("failed to resolve {}", candidate.display()));
            }
        }
    }
    bail!("could not find {name}")
}

#[cfg(unix)]
fn executable_candidates(directory: &Path, name: &str) -> Vec<PathBuf> {
    vec![directory.join(name)]
}

#[cfg(windows)]
fn executable_candidates(directory: &Path, name: &str) -> Vec<PathBuf> {
    let candidate = directory.join(name);
    if candidate.extension().is_some() {
        return vec![candidate];
    }

    env::var_os("PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
        .to_string_lossy()
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(|extension| directory.join(format!("{name}{extension}")))
        .collect()
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(windows)]
fn is_elevated() -> bool {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned_size = 0;
        let elevated = GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_size,
        ) != 0
            && elevation.TokenIsElevated != 0;
        CloseHandle(token);
        elevated
    }
}
