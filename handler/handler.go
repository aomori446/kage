package handler

import (
	"bytes"
	"errors"
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
	case config.ProtocolSocks5:
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

type UDPPacketHandler interface {
	HandleInbound(packet []byte) ([]byte, error)
	HandleOutbound(packet []byte) ([]byte, error)
}

func NewUDPPacketHandler(protocol config.Protocol, forwardAddr *socks5.Addr) (UDPPacketHandler, error) {
	switch protocol {
	case config.ProtocolSocks5:
		return &UDPSocks5PacketHandler{}, nil
	case config.ProtocolTunnel:
		return &UDPTunnelPacketHandler{ForwardAddr: forwardAddr}, nil
	default:
		return nil, config.ErrUnknownProtocol
	}
}

type UDPSocks5PacketHandler struct {
}

func (U *UDPSocks5PacketHandler) HandleInbound(packet []byte) ([]byte, error) {
	//+----+------+------+----------+----------+----------+
	//|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	//+----+------+------+----------+----------+----------+
	//| 2  |  1   |  1   | Variable |    2     | Variable |
	//+----+------+------+----------+----------+----------+
	if len(packet) < 3 {
		return nil, errors.New("packet too short")
	}

	// discard RSV and FRAG, keep Addr and DATA
	return packet[3:], nil
}

func (U *UDPSocks5PacketHandler) HandleOutbound(packet []byte) ([]byte, error) {
	//+----+------+------+----------+----------+----------+
	//|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	//+----+------+------+----------+----------+----------+
	//| 2  |  1   |  1   | Variable |    2     | Variable |
	//+----+------+------+----------+----------+----------+
	header := make([]byte, 3) // RSV = 0x0000, FRAG = 0x00
	return append(header, packet...), nil
}

type UDPTunnelPacketHandler struct {
	ForwardAddr *socks5.Addr
}

func (h *UDPTunnelPacketHandler) HandleInbound(packet []byte) ([]byte, error) {
	targetAddr := h.ForwardAddr.Bytes()
	buf := make([]byte, 0, len(targetAddr)+len(packet))
	buf = append(buf, targetAddr...)
	buf = append(buf, packet...)
	return buf, nil
}

func (h *UDPTunnelPacketHandler) HandleOutbound(packet []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(packet)
	_, err := socks5.ReadAddrFrom(buffer)
	if err != nil {
		return nil, err
	}
	// drop Addr, keep DATA
	return buffer.Bytes(), nil
}
