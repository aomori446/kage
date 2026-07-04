package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/aomori446/kage/core"
	"github.com/aomori446/kage/outbound"
)

type Inbound struct {
	Outbound   outbound.Outbound
	ListenAddr string
	TargetAddr string
}

func (c *Inbound) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	slog.Info("Tunnel inbound listening started", "addr", c.ListenAddr, "forwardTo", c.TargetAddr)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			slog.Error("Tunnel inbound accept failed", "error", err)
			continue
		}

		go func() {
			if err := c.handle(ctx, clientConn); err != nil {
				slog.Error("Tunnel handle error", "remote", clientConn.RemoteAddr(), "error", err)
			}
		}()
	}
}

func (c *Inbound) handle(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	targetAddr, err := core.ParseAddress(c.TargetAddr)
	if err != nil {
		return err
	}

	slog.Debug("Tunnel connecting", "remote", clientConn.RemoteAddr(), "target", targetAddr)

	outConn, err := c.Outbound.Dial(ctx, targetAddr)
	if err != nil {
		return err
	}
	defer outConn.Close()

	core.Relay(ctx, clientConn, outConn)
	return nil
}
