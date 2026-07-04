package outbound

import (
	"context"
	"net"

	"github.com/aomori446/kage/core"
)

type PacketConn interface {
	WriteTo(p []byte, addr *core.Address) (int, error)
	ReadFrom(p []byte) (int, *core.Address, error)
	Close() error
}

type Outbound interface {
	Dial(ctx context.Context, target *core.Address) (net.Conn, error)
	ListenUDP(ctx context.Context) (PacketConn, error)
}
