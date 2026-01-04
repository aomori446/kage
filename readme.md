# Kage (影)

Kage is a lightweight, high-performance Shadowsocks implementation written in Go. It is designed to be simple, efficient, and easy to integrate.

## Features

- **Protocol Support**: Implements the Shadowsocks protocol with modern cipher support.
- **Cipher Methods**: Supports `2022-blake3-aes-256-gcm` and other standard ciphers.
- **Modes**: Supports both TCP and UDP traffic forwarding.
- **Fast Open**: Includes TCP Fast Open (TFO) support for reduced latency.
- **Tunneling**: Can operate in tunnel mode for flexible networking setups.
- **Lightweight**: Minimal dependencies and optimized for performance.

## Installation

Ensure you have Go 1.25 or later installed.

```bash
go get github.com/aomori446/kage
```

## Usage

### As a Library

You can easily embed Kage into your own Go applications.

```go
package main

import (
	"context"
	"log"
	
	"github.com/aomori446/kage"
	"github.com/aomori446/kage/config"
)

func main() {
	cfg := &config.Config{
		ListenAddr:   "127.0.0.1:1080",
		ServerAddr:   "example.com:8388",
		Password:     "your-password",
		CipherMethod: config.CipherMethod2022blake3aes256gcm,
		Mode:         config.ModeTCP,
	}

	// Run the client
	if err := kage.RunClient(context.Background(), nil, cfg); err != nil {
		log.Fatal(err)
	}
}
```

### Configuration

The `config.Config` struct allows you to customize the behavior:

- `ListenAddr`: Local address to listen on (e.g., `127.0.0.1:1080`).
- `ServerAddr`: Remote Shadowsocks server address.
- `ForwardAddr`: Address to forward traffic to (for tunnel mode).
- `Password`: Your Shadowsocks password/key.
- `CipherMethod`: Encryption method (e.g., `CipherMethod2022blake3aes256gcm`).
- `Mode`: `ModeTCP` or `ModeUDP`.
- `Protocol`: `ProtocolSocks` or `ProtocolTunnel`.
- `FastOpen`: Enable TCP Fast Open.

## Development

### Prerequisites

- Go 1.25+

### Running Tests

```bash
go test ./...
```

## License

[MIT License](LICENSE)
