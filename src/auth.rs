use std::io::Cursor;

use anyhow::{Context, Result, bail, ensure};
use indoc::formatdoc;
use reqwest::{
    Url,
    blocking::Client,
    header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT},
    redirect::Policy,
};
use xmltree::{Element, EmitterConfig};

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
    opaque: String,
}

pub fn authenticate(
    server: Url,
    allow_http: bool,
    clear_browser_data: bool,
) -> Result<Authenticated> {
    let client = Client::builder()
        .redirect(redirect_policy(allow_http))
        .build()
        .context("failed to initialize endpoint discovery")?;

    let response = client
        .get(server)
        .send()
        .context("faile to reach VPN server")?
        .error_for_status()
        .context("VPN server returned with a 4xx/5xx response code")?;

    // Final endpoint to connect using openconnect
    let endpoint = response.url().clone();

    // Is this endpoint valid in withour current options
    ensure_allowed_url(&endpoint, allow_http, "redirected server endpoint")?;

    let client = http_client(allow_http)?;
    let init = auth_init_xml(endpoint.as_str());

    let auth_request = parse_auth_request(post_xml(&client, &endpoint, init)?, allow_http)?;

    let sso_token = browser::authenticate(
        auth_request.login_url,
        auth_request.final_url,
        &auth_request.token_cookie_name,
        clear_browser_data,
    )?;

    let finish = auth_finish_xml(auth_request.opaque, &sso_token);
    let (session_token, server_cert_hash) =
        parse_auth_complete(post_xml(&client, &endpoint, finish.clone())?)?;

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

fn auth_init_xml(endpoint: &str) -> Vec<u8> {
    return formatdoc! {r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <config-auth type="init" aggregate-auth-version="2" client="vpn">
            <version who="vpn">{anyconnect_version}</version>
            <device-id>linux-64</device-id>

            <group-select></group-select>
            <group-access>{endpoint}</group-access>

            <capabilities>
                <auth-method>single-sign-on-v2</auth-method>
            </capabilities>
        </config-auth>
        "#,
        anyconnect_version = ANYCONNECT_VERSION,
        endpoint = endpoint
    }
    .into_bytes();
}

fn auth_finish_xml(opaque: String, sso_token: &str) -> Vec<u8> {
    return formatdoc! {r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <config-auth aggregate-auth-version="2" type="auth-reply" client="vpn">
            <version who="vpn">4.7.00136</version>
            <device-id>linux-64</device-id>

            <session-token />
            <session-id />

            {opaque_element}

            <auth>
                <sso-token>{sso_token}</sso-token>
            </auth>
        </config-auth>
        "#,
        opaque_element = opaque,
        sso_token = sso_token
    }
    .into_bytes();
}

fn parse_auth_request(xml: Vec<u8>, allow_http: bool) -> Result<AuthRequest> {
    let root = parse_xml(xml)?;

    ensure!(
        root.attributes.get("type").map(String::as_str) == Some("auth-request"),
        "unsupported Cisco SSO response: expected auth-request"
    );

    let auth_element = root
        .get_child("auth")
        .context("Invalid Cisco SSO XML no auth element")?;
    let opaque_element = root
        .get_child("opaque")
        .context("Invalid Cisco SAML xml missing opaque element")?;

    ensure!(
        auth_element.attributes.get("id").map(String::as_str) == Some("main"),
        "unsupported Cisco SSO response: expected main authentication form"
    );

    match auth_element.get_child("error").and_then(Element::get_text) {
        Some(error) if !error.trim().is_empty() => {
            bail!("VPN server refused authentication: {error}")
        }
        _ => {}
    }

    let login_url = match auth_element
        .get_child("sso-v2-login")
        .and_then(Element::get_text)
    {
        Some(url) if !url.is_empty() => {
            Url::parse(url.as_ref()).context("Invalid Cisco SSO login URL")?
        }
        Some(_) => bail!("Cisco SSO Login URL is empty"),
        None => bail!("No Cisco SSO Login URL found in xml response"),
    };

    let final_url = match auth_element
        .get_child("sso-v2-login-final")
        .and_then(Element::get_text)
    {
        Some(url) if !url.is_empty() => {
            Url::parse(url.as_ref()).context("Invalid Cisco SSO final URL")?
        }
        Some(_) => bail!("Cisco SSO final URL is empty"),
        None => bail!("No Cisco SSO final URL found in xml response"),
    };

    ensure_allowed_url(&login_url, allow_http, "Cisco SSO login URL")?;
    ensure_allowed_url(&final_url, allow_http, "Cisco SSO final URL")?;

    let token_cookie_name = match auth_element
        .get_child("sso-v2-token-cookie-name")
        .and_then(Element::get_text)
        .map(String::from)
    {
        Some(name) if !name.is_empty() => name,
        Some(_) => bail!("Cisco SSO cookie name field was empty"),
        None => bail!("Cisco SSO cookie name field was not present"),
    };

    let mut opaque_string_buffer = Vec::new();
    opaque_element
        .write_with_config(
            &mut opaque_string_buffer,
            EmitterConfig::new().write_document_declaration(false),
        )
        .context("failed to serialize opaque element xml to string buffer")?;

    Ok(AuthRequest {
        login_url,
        final_url,
        token_cookie_name,
        opaque: String::from_utf8(opaque_string_buffer)
            .context("Failed to convert the opaque element xml buffer to a string")?,
    })
}

fn parse_auth_complete(xml: Vec<u8>) -> Result<(String, String)> {
    let root = parse_xml(xml)?;
    ensure!(
        root.attributes.get("type").map(String::as_str) == Some("complete"),
        "unsupported Cisco SSO response: expected complete"
    );
    let auth_element = root
        .get_child("auth")
        .context("Invalid Cisco SSO XML no auth element")?;
    ensure!(
        auth_element.attributes.get("id").map(String::as_str) == Some("success"),
        "Cisco authentication did not complete successfully"
    );

    let server_cert_hash = match root
        .get_child("config")
        .context("Invalid Cisco SSO XML response no config element")?
        .get_child("vpn-base-config")
        .context("Invalid Cisco SSO XML response no config > vpn-base-config element")?
        .get_child("server-cert-hash")
        .context("Invalid Cisco SSO XML response no config > vpn-base-config > server-cert-hash")?
        .get_text()
        .map(String::from)
    {
        Some(text) if !text.is_empty() => text,
        Some(_) => bail!("Server certificate hash is empty"),
        None => bail!("Server certificate hash does not have a value"),
    };

    let session_token = match root
        .get_child("session-token")
        .context("Invalid Cisco XML response no session-token")?
        .get_text()
        .map(String::from)
    {
        Some(text) if !text.is_empty() => text,
        Some(_) => bail!("Session token is empty"),
        None => bail!("Session token was not found"),
    };

    Ok((session_token, server_cert_hash))
}

pub(crate) fn ensure_allowed_url(url: &Url, allow_http: bool, description: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_require_an_http_override() {
        let url = Url::parse("http://vpn.example.com").unwrap();
        assert!(ensure_allowed_url(&url, false, "server endpoint").is_err());
        assert!(ensure_allowed_url(&url, true, "server endpoint").is_ok());
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
            request.opaque,
            "<opaque><tunnel-group>group</tunnel-group></opaque>"
        );
    }

    #[test]
    fn parses_completed_authentication_values() {
        let (session_token, server_cert_hash) = parse_auth_complete(
            br#"
                <config-auth type="complete">
                    <auth id="success" />
                    <session-token>session</session-token>
                    <config>
                        <vpn-base-config>
                            <server-cert-hash>sha256:hash</server-cert-hash>
                        </vpn-base-config>
                    </config>
                </config-auth>
            "#
            .to_vec(),
        )
        .unwrap();

        assert_eq!(session_token, "session");
        assert_eq!(server_cert_hash, "sha256:hash");
    }
}
