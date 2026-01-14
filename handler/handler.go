package handler

import (
	"net"
	"time"

	"github.com/aomori446/kage/config"
	"github.com/aomori446/kage/socks5"
)

type TCPHandshaker interface {
	Handshake(conn net.Conn, timeout time.Duration) (*socks5.Addr, error)
}

func NewTCPHandshaker(protocol config.Protocol, forwardAddr *socks5.Addr) (TCPHandshaker, error) {
	switch protocol {
	case config.ProtocolSocks:
		return &TCPSocks5Handshaker{}, nil
	case config.ProtocolTunnel:
		return &TCPTunnelHandshaker{ForwardAddr: forwardAddr}, nil
	default:
		return nil, config.ErrUnknownMode
	}
}

type TCPSocks5Handshaker struct{}

func (h *TCPSocks5Handshaker) Handshake(conn net.Conn, timeout time.Duration) (*socks5.Addr, error) {
	req, err := socks5.TCPHandShake(conn, timeout)
	if err != nil {
		return nil, err
	}

	if err = req.Command.Validate(socks5.Connect, conn); err != nil {
		return nil, err
	}

	if err = socks5.NewSuccessTCPResponse().ReplyTo(conn); err != nil {
		return nil, err
	}

	return req.Addr, nil
}

type TCPTunnelHandshaker struct {
	ForwardAddr *socks5.Addr
}

func (h *TCPTunnelHandshaker) Handshake(conn net.Conn, timeout time.Duration) (*socks5.Addr, error) {
	return h.ForwardAddr, nil
}