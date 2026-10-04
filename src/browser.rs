#[cfg(not(target_os = "macos"))]
use std::{env, fs, path::PathBuf};
use std::{
    process::Command,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use reqwest::Url;
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::run_return::EventLoopExtRunReturn,
    window::{Window, WindowBuilder},
};
#[cfg(not(target_os = "macos"))]
use wry::WebContext;
use wry::{NewWindowResponse, PageLoadEvent, WebView, WebViewBuilder};

#[cfg(target_os = "macos")]
use wry::{WebViewBuilderExtDarwin, WebViewExtDarwin};
#[cfg(target_os = "linux")]
use {tao::platform::unix::WindowExtUnix, wry::WebViewBuilderExtUnix};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("openconnect-sso supports Linux, macOS, and Windows");

#[cfg(target_os = "macos")]
const DATA_STORE_ID: [u8; 16] = *b"openconnect-sso!";

pub(crate) const CHILD_COMMAND: &str = "__internal-browser-auth";

// Silent single sign-on passes through each page almost immediately. A page that
// stays put for this long is assumed to be waiting for the user.
const REVEAL_AFTER_IDLE: Duration = Duration::from_millis(1500);

// Microsoft Entra ID pages that ask for input (sign-in, MFA, "stay signed in")
// carry a page id in `$Config`; the automatic SAML response form does not.
const INTERACTIVE_PAGE_SCRIPT: &str =
    r#"typeof $Config === "object" && $Config !== null && typeof $Config.pgid === "string""#;

enum BrowserEvent {
    Loaded(String),
    Open(String),
    Interactive(bool),
    #[cfg(target_os = "macos")]
    DataStores(Vec<[u8; 16]>),
    #[cfg(target_os = "macos")]
    DataStoreRemoved(Result<(), String>),
}

pub fn authenticate(
    login_url: Url,
    final_url: Url,
    cookie_name: &str,
    clear_browser_data: bool,
) -> Result<String> {
    let mut command = Command::new(std::env::current_exe().context("failed to locate executable")?);
    command
        .arg(CHILD_COMMAND)
        .arg(login_url.as_str())
        .arg(final_url.as_str())
        .arg(cookie_name);
    if clear_browser_data {
        command.arg("--clear-browser-data");
    }

    let output = command
        .output()
        .context("failed to start authentication browser process")?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        bail!("authentication browser failed: {}", error.trim());
    }

    let token = String::from_utf8(output.stdout).context("authentication token is not UTF-8")?;
    let token = token.trim_end().to_owned();
    ensure!(
        !token.is_empty(),
        "authentication browser returned no token"
    );
    Ok(token)
}

pub(crate) fn authenticate_in_process(
    login_url: Url,
    final_url: Url,
    cookie_name: &str,
    clear_browser_data: bool,
) -> Result<String> {
    let mut event_loop = EventLoopBuilder::<BrowserEvent>::with_user_event().build();

    #[cfg(target_os = "macos")]
    if clear_browser_data {
        clear_data_store(&mut event_loop)?;
    }
    #[cfg(not(target_os = "macos"))]
    let mut web_context = persistent_context(clear_browser_data)?;

    let window = WindowBuilder::new()
        .with_title("OpenConnect SSO")
        .with_inner_size(LogicalSize::new(900, 700))
        // Stay hidden while an existing session completes authentication silently.
        .with_visible(false)
        .build(&event_loop)
        .context("failed to create authentication window")?;
    let window_id = window.id();

    #[cfg(target_os = "macos")]
    let builder = WebViewBuilder::new().with_data_store_identifier(DATA_STORE_ID);
    #[cfg(not(target_os = "macos"))]
    let builder = WebViewBuilder::new_with_web_context(&mut web_context);

    let load_proxy = event_loop.create_proxy();
    let open_proxy = event_loop.create_proxy();
    let builder = builder
        .with_url(login_url.as_str())
        .with_on_page_load_handler(move |event, url| {
            if matches!(event, PageLoadEvent::Finished) {
                let _ = load_proxy.send_event(BrowserEvent::Loaded(url));
            }
        })
        // Default popup windows are owned by the platform webview and can outlive
        // this authentication window. Keep the entire login flow in one window.
        .with_new_window_req_handler(move |url, _| {
            let _ = open_proxy.send_event(BrowserEvent::Open(url));
            NewWindowResponse::Deny
        });

    #[cfg(target_os = "linux")]
    let webview = builder
        .build_gtk(
            window
                .default_vbox()
                .context("authentication window has no GTK container")?,
        )
        .context("failed to create authentication browser")?;
    #[cfg(not(target_os = "linux"))]
    let webview = builder
        .build(&window)
        .context("failed to create authentication browser")?;

    let script_proxy = event_loop.create_proxy();
    let mut window = Some(window);
    let mut webview = Some(webview);
    let mut result = None;
    let mut reveal_at = Some(Instant::now() + REVEAL_AFTER_IDLE);
    event_loop.run_return(|event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(BrowserEvent::Open(url)) => {
                let Some(browser) = webview.as_ref() else {
                    return;
                };
                if let Err(error) = browser.load_url(&url) {
                    result = Some(Err(error).context("failed to open authentication page"));
                    drop(webview.take());
                    drop(window.take());
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::UserEvent(BrowserEvent::Loaded(url)) => {
                let loaded_url = match Url::parse(&url) {
                    Ok(url) => url,
                    Err(_) => return,
                };
                if loaded_url == final_url {
                    result = webview
                        .as_ref()
                        .map(|browser| find_cookie(browser, &final_url, cookie_name));
                    drop(webview.take());
                    drop(window.take());
                    *control_flow = ControlFlow::Exit;
                    return;
                }
                if reveal_at.is_none() {
                    return;
                }
                reveal_at = Some(Instant::now() + REVEAL_AFTER_IDLE);
                if let Some(browser) = webview.as_ref() {
                    let proxy = script_proxy.clone();
                    // If the script cannot run, the idle timer still reveals the window.
                    let _ = browser.evaluate_script_with_callback(
                        INTERACTIVE_PAGE_SCRIPT,
                        move |interactive| {
                            let _ = proxy.send_event(BrowserEvent::Interactive(
                                interactive.trim() == "true",
                            ));
                        },
                    );
                }
            }
            Event::UserEvent(BrowserEvent::Interactive(true)) if reveal_at.is_some() => {
                reveal_at = None;
                reveal(window.as_ref());
            }
            Event::WindowEvent {
                window_id: closed_window,
                event: WindowEvent::CloseRequested,
                ..
            } if closed_window == window_id => {
                result = Some(Err(anyhow!("authentication cancelled")));
                drop(webview.take());
                drop(window.take());
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }

        if matches!(*control_flow, ControlFlow::Exit) {
            return;
        }
        match reveal_at {
            Some(deadline) if Instant::now() >= deadline => {
                reveal_at = None;
                reveal(window.as_ref());
            }
            Some(deadline) => *control_flow = ControlFlow::WaitUntil(deadline),
            None => {}
        }
    });

    drop(webview);
    drop(window);
    #[cfg(not(target_os = "macos"))]
    drop(web_context);
    drop(event_loop);

    result.unwrap_or_else(|| Err(anyhow!("authentication browser exited unexpectedly")))
}

fn reveal(window: Option<&Window>) {
    if let Some(window) = window {
        window.set_visible(true);
        window.set_focus();
    }
}

#[cfg(not(target_os = "macos"))]
fn persistent_context(clear_browser_data: bool) -> Result<WebContext> {
    let path = browser_data_directory()?;
    if clear_browser_data && path.exists() {
        fs::remove_dir_all(&path)
            .with_context(|| format!("failed to clear browser data at {}", path.display()))?;
    }
    fs::create_dir_all(&path)
        .with_context(|| format!("failed to create browser data directory {}", path.display()))?;
    Ok(WebContext::new(Some(path)))
}

#[cfg(target_os = "linux")]
fn browser_data_directory() -> Result<PathBuf> {
    if let Some(path) = env::var_os("XDG_DATA_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path).join("openconnect-sso/webview"));
    }
    Ok(PathBuf::from(
        env::var_os("HOME")
            .context("neither XDG_DATA_HOME nor HOME is set; cannot persist browser data")?,
    )
    .join(".local/share/openconnect-sso/webview"))
}

#[cfg(target_os = "windows")]
fn browser_data_directory() -> Result<PathBuf> {
    Ok(PathBuf::from(
        env::var_os("LOCALAPPDATA")
            .context("LOCALAPPDATA is not set; cannot persist browser data")?,
    )
    .join("openconnect-sso/webview"))
}

#[cfg(target_os = "macos")]
fn clear_data_store(event_loop: &mut tao::event_loop::EventLoop<BrowserEvent>) -> Result<()> {
    let proxy = event_loop.create_proxy();
    WebView::fetch_data_store_identifiers(move |identifiers| {
        let _ = proxy.send_event(BrowserEvent::DataStores(identifiers));
    })
    .context("failed to inspect browser data")?;

    let mut exists = None;
    event_loop.run_return(|event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::UserEvent(BrowserEvent::DataStores(identifiers)) = event {
            exists = Some(identifiers.contains(&DATA_STORE_ID));
            *control_flow = ControlFlow::Exit;
        }
    });

    if exists != Some(true) {
        return Ok(());
    }

    let proxy = event_loop.create_proxy();
    WebView::remove_data_store(&DATA_STORE_ID, move |result| {
        let _ = proxy.send_event(BrowserEvent::DataStoreRemoved(
            result.map_err(|error| error.to_string()),
        ));
    });

    let mut result = None;
    event_loop.run_return(|event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::UserEvent(BrowserEvent::DataStoreRemoved(removed)) = event {
            result = Some(removed);
            *control_flow = ControlFlow::Exit;
        }
    });

    match result {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => bail!("failed to clear browser data: {error}"),
        None => bail!("browser data clearing did not complete"),
    }
}

fn find_cookie(webview: &WebView, final_url: &Url, name: &str) -> Result<String> {
    let host = final_url
        .host_str()
        .context("Cisco SSO final URL has no hostname")?;
    webview
        .cookies()
        .context("failed to read authentication cookies")?
        .into_iter()
        .find(|cookie| {
            cookie.name() == name
                && cookie.domain().is_none_or(|domain| {
                    let domain = domain.trim_start_matches('.');
                    host == domain || host.ends_with(&format!(".{domain}"))
                })
        })
        .map(|cookie| cookie.value().to_owned())
        .with_context(|| format!("authentication completed without the expected {name:?} cookie"))
}
