package raw

import (
	"context"
	"net"

	"github.com/aomori446/kage/core"
	"github.com/aomori446/kage/outbound"
)

type Outbound struct{}

func NewOutbound() *Outbound {
	return &Outbound{}
}

func (o *Outbound) Dial(ctx context.Context, target *core.Address) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target.String())
}

func (o *Outbound) ListenUDP(ctx context.Context) (outbound.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &RawPacketConn{conn: conn}, nil
}

type RawPacketConn struct {
	conn *net.UDPConn
}

func (r *RawPacketConn) WriteTo(p []byte, addr *core.Address) (int, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	return r.conn.WriteTo(p, udpAddr)
}

func (r *RawPacketConn) ReadFrom(p []byte) (int, *core.Address, error) {
	n, fromAddr, err := r.conn.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	coreAddr, err := core.ParseAddress(fromAddr.String())
	if err != nil {
		return 0, nil, err
	}
	return n, coreAddr, nil
}

func (r *RawPacketConn) Close() error {
	return r.conn.Close()
}
