#[cfg(not(target_os = "macos"))]
use std::{env, fs, path::PathBuf};

#[cfg(target_os = "macos")]
use anyhow::bail;
use anyhow::{Context, Result, anyhow};
use reqwest::Url;
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::run_return::EventLoopExtRunReturn,
    window::WindowBuilder,
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

enum BrowserEvent {
    Loaded(String),
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
    let mut event_loop = EventLoopBuilder::<BrowserEvent>::with_user_event().build();

    #[cfg(target_os = "macos")]
    if clear_browser_data {
        clear_data_store(&mut event_loop)?;
    }
    #[cfg(not(target_os = "macos"))]
    let mut web_context = persistent_context(clear_browser_data)?;

    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("OpenConnect SSO")
        .with_inner_size(LogicalSize::new(900, 700))
        .build(&event_loop)
        .context("failed to create authentication window")?;
    let window_id = window.id();

    #[cfg(target_os = "macos")]
    let builder = WebViewBuilder::new().with_data_store_identifier(DATA_STORE_ID);
    #[cfg(not(target_os = "macos"))]
    let builder = WebViewBuilder::new_with_web_context(&mut web_context);

    let builder = builder
        .with_url(login_url.as_str())
        .with_on_page_load_handler(move |event, url| {
            if matches!(event, PageLoadEvent::Finished) {
                let _ = proxy.send_event(BrowserEvent::Loaded(url));
            }
        })
        .with_new_window_req_handler(|_, _| NewWindowResponse::Allow);

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

    let mut result = None;
    event_loop.run_return(|event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(BrowserEvent::Loaded(url)) => {
                let loaded_url = match Url::parse(&url) {
                    Ok(url) => url,
                    Err(_) => return,
                };
                if loaded_url == final_url {
                    result = Some(find_cookie(&webview, &final_url, cookie_name));
                    window.set_visible(false);
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::WindowEvent {
                window_id: closed_window,
                event: WindowEvent::CloseRequested,
                ..
            } if closed_window == window_id => {
                result = Some(Err(anyhow!("authentication cancelled")));
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });

    drop(webview);
    drop(window);
    result.unwrap_or_else(|| Err(anyhow!("authentication browser exited unexpectedly")))
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
