package shadowsocks

import (
	"context"
	"net"

	"github.com/aomori446/kage/core"
	"github.com/aomori446/kage/outbound"
)

type Outbound struct {
	ServerAddr string
	Method     string
	Key        []byte
}

func NewOutbound(serverAddr, method string, key []byte) *Outbound {
	return &Outbound{
		ServerAddr: serverAddr,
		Method:     method,
		Key:        key,
	}
}

func (o *Outbound) Dial(ctx context.Context, target *core.Address) (net.Conn, error) {
	return NewConn(o.ServerAddr, o.Method, o.Key, target, nil)
}

func (o *Outbound) ListenUDP(ctx context.Context) (outbound.PacketConn, error) {
	return NewUDPRelay(o.Method, o.Key, o.ServerAddr)
}
