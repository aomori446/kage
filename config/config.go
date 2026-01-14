package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

// Config holds the application configuration.
type Config struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`

	LocalAddr string `json:"local_address"`
	LocalPort int    `json:"local_port"`

	Protocol    Protocol `json:"protocol"`
	ForwardAddr string   `json:"forward_address"`
	ForwardPort int      `json:"forward_port"`

	Mode Mode `json:"mode"`

	FastOpen bool `json:"fast_open"`

	Password string       `json:"password"`
	Method   CipherMethod `json:"method"`
}

func (c *Config) GetServerAddr() string {
	return net.JoinHostPort(c.Server, strconv.Itoa(c.ServerPort))
}

func (c *Config) GetLocalAddr() string {
	return net.JoinHostPort(c.LocalAddr, strconv.Itoa(c.LocalPort))
}

func (c *Config) GetForwardAddr() string {
	return net.JoinHostPort(c.ForwardAddr, strconv.Itoa(c.ForwardPort))
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.LocalAddr == "" {
		return errors.New("local_address is required")
	}
	if c.LocalPort == 0 {
		return errors.New("local_port is required")
	}

	if c.Server == "" {
		return errors.New("server is required")
	}
	if c.ServerPort == 0 {
		return errors.New("server_port is required")
	}

	if c.Password == "" {
		return errors.New("password is required")
	}
	if c.Method == "" {
		return errors.New("method is required")
	}

	switch c.Mode {
	case ModeTCPOnly, ModeUDPOnly, ModeTCPAndUDP:
		// valid
	default:
		return fmt.Errorf("%w: %s", ErrUnknownMode, c.Mode)
	}

	switch c.Protocol {
	case ProtocolSocks:
		// valid
	case ProtocolTunnel:
		if c.ForwardAddr == "" {
			return errors.New("forward_address is required for tunnel protocol")
		}
		if c.ForwardPort == 0 {
			return errors.New("forward_port is required for tunnel protocol")
		}
	default:
		return fmt.Errorf("%w: %s", ErrUnknownProtocol, c.Protocol)
	}

	return nil
}