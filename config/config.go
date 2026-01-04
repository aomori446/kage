package config

import "errors"

type Mode string

const (
	ModeTCP Mode = "tcp"
	ModeUDP Mode = "udp"
)

type CipherMethod string

const (
	CipherMethod2022blake3aes128gcm        CipherMethod = "2022-blake3-aes-128-gcm"
	CipherMethod2022blake3aes256gcm        CipherMethod = "2022-blake3-aes-256-gcm"
	CipherMethod2022blake3chacha20poly1305 CipherMethod = "2022-blake3-chacha20-poly1305"
)

var (
	ErrUnknownMode     = errors.New("config: unknown Mode")
	ErrUnknownProtocol = errors.New("config: unknown Protocol")
)

type Protocol string

const (
	ProtocolSocks5 Protocol = "socks5"
	ProtocolTunnel Protocol = "tunnel"
)

type Config struct {
	ListenAddr  string
	ForwardAddr string // used for ProtocolTunnel only
	ServerAddr  string
	
	Mode     Mode
	Protocol Protocol
	
	FastOpen bool
	
	Password     string
	CipherMethod CipherMethod
}
