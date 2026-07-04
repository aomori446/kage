# kage

A simple, lightweight, and high-performance proxy tool written in Go.
It supports multiple local inbound connection types and forwards traffic to remote servers with configurable outbound protocols, including **Shadowsocks 2022** and **Raw (Direct/Freedom)** outbound.

## Features & Architecture

This tool is designed to provide flexible routing, multiple protocol support, and secure communications.

### Inbound (Local Connection Handling)
It processes incoming connections from user applications (browsers or other tools). A single process can run multiple inbound handlers simultaneously:
- **SOCKS5**: A versatile proxy protocol. Supports both TCP and **UDP (Shadowsocks 2022 / SIP022)** relays.
- **HTTP Proxy**: A standard proxy protocol for HTTP communications.
- **TCP Tunnel**: A port forwarding utility that relays TCP connections from a local port to a remote target address.
- **Shadowsocks**: A secure proxy protocol. Listens for incoming encrypted Shadowsocks 2022 connections, decrypts the request, and forwards it to the target.

### Outbound (Remote Connections)
`kage` decouples inbounds from outbounds via a generic interface, supporting:
- **Shadowsocks**: Encrypts and relays outbound traffic to a remote server. Supports the latest **Shadowsocks 2022** specification (AEAD-2022) with advanced encryption methods and UDP relay.
- **Raw (Direct)**: Bypasses proxies and establishes direct TCP connections to target destinations.

---

## Installation

Building from source requires Go (version 1.25 or higher).

```bash
# Clone the repository
git clone https://github.com/aomori446/kage.git
cd kage

# Build the binary
go build ./cmd/kage
```

---

## Project Structure

The project follows the standard Go project layout:

```text
/kage/
├── cmd/
│   └── kage/
│       ├── main.go          # CLI Entrypoint
│       ├── config.go        # Configuration loader
│       └── logger.go        # Logger initialization
├── core/                    # Common infrastructure (Address parsing, TCP Relay)
├── inbound/                 # Inbound protocol handlers
│   ├── http/                # HTTP Proxy server
│   ├── shadowsocks/         # Shadowsocks 2022 Proxy server (TCP support)
│   ├── socks5/              # SOCKS5 Proxy server (with TCP & UDP support)
│   └── tunnel/              # TCP Port Forwarding Tunnel
├── outbound/                # Outbound protocol handlers
│   ├── outbound.go          # Outbound interface
│   ├── raw/                 # Direct Outbound (no proxy)
│   └── shadowsocks/         # Shadowsocks 2022 Outbound
└── testdata/                # Example configurations and test data
    └── config.json          # Example configuration file
```

---

## Usage

Start the proxy server by specifying a configuration file. By default, it looks for `testdata/config.json`.

```bash
./kage -c testdata/config.json
```

---

## Configuration File (`config.json`)

Configurations are specified in JSON format. Below is an example:

```json
{
  "outbound": "shadowsocks",
  "server": "example.com:8388",
  "method": "2022-blake3-aes-256-gcm",
  "key": "rwQc8qPXVsRpGx3uW+Y3Lj4Y42yF9Bs0xg1pmx8/+bo=",
  "log_level": "info",
  "inbounds": [
    {
      "type": "socks5",
      "listen": "127.0.0.1:1080",
      "fast_open": true,
      "udp": true
    },
    {
      "type": "http",
      "listen": "127.0.0.1:8080"
    },
    {
      "type": "tunnel",
      "listen": "127.0.0.1:5432",
      "target": "10.0.0.2:5432"
    },
    {
      "type": "shadowsocks",
      "listen": "127.0.0.1:8388"
    }
  ]
}
```

### Parameters

- `outbound`: The outbound protocol type. Supported values: `"shadowsocks"` (default) or `"raw"` (direct connection).
- `server`: The host and port (`IP:Port`) of the remote Shadowsocks server (only required for `"shadowsocks"` outbound).
- `method`: The encryption method for Shadowsocks (only required for `"shadowsocks"` outbound).
  - Supported: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`
- `key`: The pre-shared master key (PSK) for Shadowsocks (only required for `"shadowsocks"` outbound). **Note:** Must be a **Base64 encoded** string.
- `log_level`: The logging verbosity (`debug`, `info`, `warn`, `error`).
- `inbounds`: An array of local ports to listen on.
  - `type`: The inbound type, one of: `socks5`, `http`, `tunnel`, `shadowsocks`.
  - `listen`: The local IP and port to listen on (`IP:Port`).
  - `target`: The destination target address (`IP:Port`) (required only when `type` is `tunnel`).
  - `fast_open`: (Optional) Set to `true` to enable TCP Fast Open.
  - `udp`: (Optional) Set to `true` to enable UDP relay (SOCKS5 only).

---

## License

MIT License
