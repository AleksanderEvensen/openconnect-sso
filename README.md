# openconnect-sso

Cisco AnyConnect SSO-v2 authentication for OpenConnect. It opens the VPN provider's web login in a persistent native macOS browser, then starts OpenConnect with the resulting session.

## Requirements

- Apple Silicon Mac
- macOS 14 or newer
- OpenConnect
- Rust (for source installation)

```sh
brew install openconnect
cargo install --path .
```

## Usage

```sh
openconnect-sso --server vpn.ntnu.no
```

Arguments after `--` are passed unchanged to OpenConnect:

```sh
openconnect-sso --server vpn.ntnu.no -- --no-dtls --verbose
```

Force a fresh browser session:

```sh
openconnect-sso --server vpn.ntnu.no --clear-browser-data
```

Only HTTPS endpoints are accepted by default. For local testing, HTTP must be both explicit and deliberately enabled:

```sh
openconnect-sso --server http://vpn.example.test --allow-http-endpoint
```

The application does not collect or store passwords. WKWebView persists its own browser cookies and site data so existing identity-provider sessions can be reused.

## Scope

This application supports Cisco AnyConnect SSO-v2 browser authentication. Use OpenConnect directly for other VPN protocols or authentication methods.
