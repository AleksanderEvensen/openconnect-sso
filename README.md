# openconnect-sso

Wrapper script for OpenConnect supporting Azure AD (SAMLv2) authentication
to Cisco SSL-VPNs

## Installation

OpenConnect is required before running this tool

### MacOS

```sh
brew install openconnect
```

### Windows Linux

On your own check out this link: https://www.infradead.org/openconnect/download.html


### Install dependencies

```sh
uv sync
```


## Usage


```sh
$ uv run openconnect-sso --server <serverName> # eg https://vpn.ntnu.no
```


