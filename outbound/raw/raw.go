package raw

import (
	"context"
	"net"

	"github.com/aomori446/kage/core"
)

type Outbound struct{}

func NewOutbound() *Outbound {
	return &Outbound{}
}

func (o *Outbound) Dial(ctx context.Context, target *core.Address) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target.String())
}
