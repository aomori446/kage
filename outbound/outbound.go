package outbound

import (
	"context"
	"net"

	"github.com/aomori446/kage/core"
)

type Outbound interface {
	Dial(ctx context.Context, target *core.Address) (net.Conn, error)
}
