package config

import "errors"

// Mode defines the operation mode of the client (TCP, UDP, or both).
type Mode string

const (
	ModeTCPOnly   Mode = "tcp_only"
)

// Protocol defines the proxy protocol used by the client (Socks or Tunnel).
type Protocol string

const (
	ProtocolSocks  Protocol = "socks"
	ProtocolTunnel Protocol = "tunnel"
)

// CipherMethod defines the encryption method used for Shadowsocks.
type CipherMethod string

const (
	CipherMethod2022blake3aes128gcm        CipherMethod = "2022-blake3-aes-128-gcm"
	CipherMethod2022blake3aes256gcm        CipherMethod = "2022-blake3-aes-256-gcm"
	CipherMethod2022blake3chacha20poly1305 CipherMethod = "2022-blake3-chacha20-poly1305"
)

var (
	ErrUnknownMode     = errors.New("config: unknown Mode")
	ErrUnknownProtocol = errors.New("config: unknown Protocol")
	ErrConfigNotFound  = errors.New("config: file not found")
)
