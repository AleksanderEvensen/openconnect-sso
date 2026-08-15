# openconnect-sso

Cisco AnyConnect SSO-v2 authentication for OpenConnect. It opens the VPN provider's web login in a persistent native browser, then starts OpenConnect with the resulting session.

## Requirements

- OpenConnect available in `PATH`
- Rust, when installing from source
- One of:
  - macOS 14 or newer
  - Linux with X11 or Wayland
  - Windows 10 or newer with WebView2

### macOS

```sh
brew install openconnect
cargo install --path .
```

### Ubuntu/Debian

```sh
sudo apt install openconnect libwebkit2gtk-4.1-dev build-essential pkg-config
cargo install --path .
```

### Fedora

```sh
sudo dnf install openconnect webkit2gtk4.1-devel gtk3-devel gcc pkgconf-pkg-config
cargo install --path .
```

### Arch Linux

```sh
sudo pacman -S openconnect webkit2gtk-4.1 base-devel
cargo install --path .
```

### Windows

Install Rust and the [official OpenConnect Windows package](https://www.infradead.org/openconnect/packages.html), ensure `openconnect.exe` is in `PATH`, then run:

```powershell
cargo install --path .
```

OpenConnect needs Administrator privileges to configure the tunnel. Run `openconnect-sso` from a terminal started with **Run as administrator**.

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

The application does not collect or store passwords. The platform browser persists its own cookies and site data so existing identity-provider sessions can be reused:

- WKWebView on macOS
- WebKitGTK on Linux
- WebView2 on Windows

## Scope

This application supports Cisco AnyConnect SSO-v2 browser authentication. Use OpenConnect directly for other VPN protocols or authentication methods.
