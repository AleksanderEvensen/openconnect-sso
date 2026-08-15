use std::io::Cursor;

use anyhow::{Context, Result, bail, ensure};
use reqwest::{
    Url,
    blocking::Client,
    header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT},
    redirect::Policy,
};
use xmltree::{Element, EmitterConfig, XMLNode};

use crate::browser;

const ANYCONNECT_VERSION: &str = "4.7.00136";
const USER_AGENT_VALUE: &str = "AnyConnect Linux_64 4.7.00136";

pub struct Authenticated {
    pub server: Url,
    pub session_token: String,
    pub server_cert_hash: String,
}

struct AuthRequest {
    login_url: Url,
    final_url: Url,
    token_cookie_name: String,
    opaque: Element,
}

pub fn server_url(value: &str, allow_http: bool) -> Result<Url> {
    let url = if value.contains("://") {
        Url::parse(value).context("invalid --server URL")?
    } else {
        Url::parse(&format!("https://{value}")).context("invalid --server hostname")?
    };
    ensure_allowed_url(&url, allow_http, "server endpoint")?;
    ensure!(
        url.host_str().is_some(),
        "server URL must contain a hostname"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "credentials are not allowed in the server URL"
    );
    Ok(url)
}

pub fn authenticate(
    server: Url,
    allow_http: bool,
    clear_browser_data: bool,
) -> Result<Authenticated> {
    let endpoint = Client::builder()
        .redirect(redirect_policy(allow_http))
        .build()
        .context("failed to initialize endpoint discovery")?
        .get(server)
        .send()
        .context("failed to reach VPN server")?
        .error_for_status()
        .context("VPN server rejected endpoint discovery")?
        .url()
        .clone();
    ensure_allowed_url(&endpoint, allow_http, "redirected server endpoint")?;

    let client = http_client(allow_http)?;
    let init = auth_init_xml(endpoint.as_str())?;
    let request = parse_auth_request(post_xml(&client, &endpoint, init)?, allow_http)?;

    let sso_token = browser::authenticate(
        request.login_url,
        request.final_url,
        &request.token_cookie_name,
        clear_browser_data,
    )?;

    let finish = auth_finish_xml(request.opaque, &sso_token)?;
    let (session_token, server_cert_hash) =
        parse_auth_complete(post_xml(&client, &endpoint, finish)?)?;

    Ok(Authenticated {
        server: endpoint,
        session_token,
        server_cert_hash,
    })
}

fn http_client(allow_http: bool) -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert("X-Transcend-Version", HeaderValue::from_static("1"));
    headers.insert("X-Aggregate-Auth", HeaderValue::from_static("1"));
    headers.insert("X-Support-HTTP-Auth", HeaderValue::from_static("true"));

    Client::builder()
        .default_headers(headers)
        .cookie_store(true)
        .redirect(redirect_policy(allow_http))
        .build()
        .context("failed to initialize HTTP client")
}

fn redirect_policy(allow_http: bool) -> Policy {
    Policy::custom(move |attempt| {
        if attempt.url().scheme() == "http" && !allow_http {
            attempt.error("refusing redirect to HTTP; pass --allow-http-endpoint to permit it")
        } else {
            attempt.follow()
        }
    })
}

fn post_xml(client: &Client, endpoint: &Url, body: Vec<u8>) -> Result<Vec<u8>> {
    Ok(client
        .post(endpoint.clone())
        .body(body)
        .send()
        .context("Cisco authentication request failed")?
        .error_for_status()
        .context("Cisco authentication request was rejected")?
        .bytes()
        .context("failed to read Cisco authentication response")?
        .to_vec())
}

fn auth_init_xml(endpoint: &str) -> Result<Vec<u8>> {
    let mut root = element("config-auth", None);
    root.attributes.insert("client".into(), "vpn".into());
    root.attributes.insert("type".into(), "init".into());
    root.attributes
        .insert("aggregate-auth-version".into(), "2".into());

    let mut version = element("version", Some(ANYCONNECT_VERSION));
    version.attributes.insert("who".into(), "vpn".into());
    push(&mut root, version);
    push(&mut root, element("device-id", Some("linux-64")));
    push(&mut root, element("group-select", Some("")));
    push(&mut root, element("group-access", Some(endpoint)));

    let mut capabilities = element("capabilities", None);
    push(
        &mut capabilities,
        element("auth-method", Some("single-sign-on-v2")),
    );
    push(&mut root, capabilities);
    write_xml(&root)
}

fn auth_finish_xml(opaque: Element, sso_token: &str) -> Result<Vec<u8>> {
    let mut root = element("config-auth", None);
    root.attributes.insert("client".into(), "vpn".into());
    root.attributes.insert("type".into(), "auth-reply".into());
    root.attributes
        .insert("aggregate-auth-version".into(), "2".into());

    let mut version = element("version", Some(ANYCONNECT_VERSION));
    version.attributes.insert("who".into(), "vpn".into());
    push(&mut root, version);
    push(&mut root, element("device-id", Some("linux-64")));
    push(&mut root, element("session-token", None));
    push(&mut root, element("session-id", None));
    push(&mut root, opaque);

    let mut auth = element("auth", None);
    push(&mut auth, element("sso-token", Some(sso_token)));
    push(&mut root, auth);
    write_xml(&root)
}

fn parse_auth_request(xml: Vec<u8>, allow_http: bool) -> Result<AuthRequest> {
    let root = parse_xml(xml)?;
    ensure!(
        root.attributes.get("type").map(String::as_str) == Some("auth-request"),
        "unsupported Cisco SSO response: expected auth-request"
    );
    let auth = child(&root, "auth")?;
    ensure!(
        auth.attributes.get("id").map(String::as_str) == Some("main"),
        "unsupported Cisco SSO response: expected main authentication form"
    );
    if let Some(error) = optional_text(auth, "error")
        && !error.trim().is_empty()
    {
        bail!("VPN server refused authentication: {error}");
    }

    let login_url =
        Url::parse(&required_text(auth, "sso-v2-login")?).context("invalid Cisco SSO login URL")?;
    let final_url = Url::parse(&required_text(auth, "sso-v2-login-final")?)
        .context("invalid Cisco SSO final URL")?;
    ensure_allowed_url(&login_url, allow_http, "Cisco SSO login URL")?;
    ensure_allowed_url(&final_url, allow_http, "Cisco SSO final URL")?;

    Ok(AuthRequest {
        login_url,
        final_url,
        token_cookie_name: required_text(auth, "sso-v2-token-cookie-name")?,
        opaque: child(&root, "opaque")?.clone(),
    })
}

fn parse_auth_complete(xml: Vec<u8>) -> Result<(String, String)> {
    let root = parse_xml(xml)?;
    ensure!(
        root.attributes.get("type").map(String::as_str) == Some("complete"),
        "unsupported Cisco SSO response: expected complete"
    );
    let auth = child(&root, "auth")?;
    ensure!(
        auth.attributes.get("id").map(String::as_str) == Some("success"),
        "Cisco authentication did not complete successfully"
    );
    let config = child(&root, "config")?;
    let vpn_config = child(config, "vpn-base-config")?;

    Ok((
        required_text(&root, "session-token")?,
        required_text(vpn_config, "server-cert-hash")?,
    ))
}

fn ensure_allowed_url(url: &Url, allow_http: bool, description: &str) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => bail!(
            "{description} uses HTTP; pass --allow-http-endpoint to permit plaintext authentication"
        ),
        scheme => bail!("{description} uses unsupported URL scheme {scheme:?}"),
    }
}

fn parse_xml(xml: Vec<u8>) -> Result<Element> {
    Element::parse(Cursor::new(xml)).context("unsupported or malformed Cisco SSO response")
}

fn child<'a>(element: &'a Element, name: &str) -> Result<&'a Element> {
    element
        .get_child(name)
        .with_context(|| format!("unsupported Cisco SSO response: missing <{name}>"))
}

fn required_text(element: &Element, name: &str) -> Result<String> {
    optional_text(element, name)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("unsupported Cisco SSO response: missing <{name}> value"))
}

fn optional_text(element: &Element, name: &str) -> Option<String> {
    element
        .get_child(name)
        .and_then(Element::get_text)
        .map(|value| value.into_owned())
}

fn element(name: &str, text: Option<&str>) -> Element {
    let mut element = Element::new(name);
    if let Some(text) = text {
        element.children.push(XMLNode::Text(text.into()));
    }
    element
}

fn push(parent: &mut Element, child: Element) {
    parent.children.push(XMLNode::Element(child));
}

fn write_xml(element: &Element) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    element
        .write_with_config(
            &mut output,
            EmitterConfig::new()
                .perform_indent(true)
                .write_document_declaration(true),
        )
        .context("failed to construct Cisco authentication request")?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_default_to_https_and_require_an_http_override() {
        assert_eq!(
            server_url("vpn.example.com", false).unwrap().as_str(),
            "https://vpn.example.com/"
        );
        assert!(server_url("http://vpn.example.com", false).is_err());
        assert!(server_url("http://vpn.example.com", true).is_ok());
    }

    #[test]
    fn parses_cisco_auth_request() {
        let request = parse_auth_request(
            br#"<config-auth type="auth-request"><auth id="main"><sso-v2-login>https://login.example.com/</sso-v2-login><sso-v2-login-final>https://vpn.example.com/done</sso-v2-login-final><sso-v2-token-cookie-name>token</sso-v2-token-cookie-name></auth><opaque><tunnel-group>group</tunnel-group></opaque></config-auth>"#.to_vec(),
            false,
        )
        .unwrap();

        assert_eq!(request.token_cookie_name, "token");
        assert_eq!(
            request
                .opaque
                .get_child("tunnel-group")
                .unwrap()
                .get_text()
                .unwrap(),
            "group"
        );
    }
}
