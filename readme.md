# Kage (影)

## UDP通信はsupportしております！！

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
	"log/slog"
	"os"
	
	"github.com/aomori446/kage"
	"github.com/aomori446/kage/config"
)

func main() {
	cfg := &config.Config{
		LocalAddr:  "127.0.0.1",
		LocalPort:  1080,
		Server:     "example.com",
		ServerPort: 8388,
		Password:   "your-password",
		Method:     config.CipherMethod2022blake3aes256gcm,
		Mode:       config.ModeTCPOnly,
		Protocol:   config.ProtocolSocks,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create the client
	client, err := kage.NewClient(cfg, logger)
	if err != nil {
		log.Fatal(err)
	}

	// Run the client
	if err := client.Serve(context.Background()); err != nil {
		log.Fatal(err)
	}
}
```

### Configuration

The `config.Config` struct allows you to customize the behavior:

- `LocalAddr`, `LocalPort`: Local address and port to listen on.
- `Server`, `ServerPort`: Remote Shadowsocks server address and port.
- `ForwardAddr`, `ForwardPort`: Address and port to forward traffic to (for tunnel mode).
- `Password`: Your Shadowsocks password/key.
- `Method`: Encryption method (e.g., `CipherMethod2022blake3aes256gcm`).
- `Mode`: `ModeTCPOnly`, `ModeUDPOnly`, or `ModeTCPAndUDP`.
- `Protocol`: `ProtocolSocks` or `ProtocolTunnel`.
- `FastOpen`: Enable TCP Fast Open.

## Development

### Prerequisites

- Go 1.25+

### Running Tests

```bash
go test ./...
```

## TODO

- [ ] Implement server side
- [ ] Add plugin support (SIPs)
- [ ] Support multiple servers (Load Balancing / Failover)
- [ ] Add ACL / Routing support
- [ ] Improve test coverage

## License

[MIT License](LICENSE)
