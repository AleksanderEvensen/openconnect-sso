use anyhow::{Context, Result, anyhow, bail};
use reqwest::Url;
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::run_return::EventLoopExtRunReturn,
    window::WindowBuilder,
};
use wry::{
    NewWindowResponse, PageLoadEvent, WebView, WebViewBuilder, WebViewBuilderExtDarwin,
    WebViewExtDarwin,
};

const DATA_STORE_ID: [u8; 16] = *b"openconnect-sso!";

enum BrowserEvent {
    Loaded(String),
    DataStores(Vec<[u8; 16]>),
    DataStoreRemoved(Result<(), String>),
}

pub fn authenticate(
    login_url: Url,
    final_url: Url,
    cookie_name: &str,
    clear_browser_data: bool,
) -> Result<String> {
    let mut event_loop = EventLoopBuilder::<BrowserEvent>::with_user_event().build();
    if clear_browser_data {
        clear_data_store(&mut event_loop)?;
    }

    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("OpenConnect SSO")
        .with_inner_size(LogicalSize::new(900, 700))
        .build(&event_loop)
        .context("failed to create authentication window")?;
    let window_id = window.id();

    let webview = WebViewBuilder::new()
        .with_data_store_identifier(DATA_STORE_ID)
        .with_url(login_url.as_str())
        .with_on_page_load_handler(move |event, url| {
            if matches!(event, PageLoadEvent::Finished) {
                let _ = proxy.send_event(BrowserEvent::Loaded(url));
            }
        })
        .with_new_window_req_handler(|_, _| NewWindowResponse::Allow)
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
