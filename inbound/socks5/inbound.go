package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"

	"github.com/aomori446/kage/core"
	"github.com/aomori446/kage/outbound"
	"github.com/aomori446/kage/outbound/shadowsocks"
)

type Inbound struct {
	Outbound   outbound.Outbound
	ListenAddr string
	FastOpen   bool

	UDP bool
}

func (c *Inbound) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s failed: %w", c.ListenAddr, err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				err = fmt.Errorf("accept new connection failed: %w", err)
			} else {
				err = nil
			}
			return err
		}

		go c.handleConn(ctx, clientConn)
	}
}

func (c *Inbound) handleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	handshakeRes, err := Handshake(ctx, clientConn, c.FastOpen)
	if err != nil {
		slog.Debug("[SOCKS5] handshake failed", "client", clientConn.RemoteAddr(), "err", err)
		return
	}

	if handshakeRes.Command == 0x03 {
		if !c.UDP {
			slog.Debug("[SOCKS5] UDP Associate rejected: UDP disabled", "client", clientConn.RemoteAddr())
			return
		}
		if err = c.handleUDP(ctx, clientConn); err != nil {
			slog.Debug("[SOCKS5] UDP proxy connection failed", "client", clientConn.RemoteAddr(), "err", err)
		}
		return
	}

	if err = c.handleTCP(ctx, clientConn, handshakeRes.TargetAddress, handshakeRes.InitialPayload); err != nil {
		slog.Debug("[SOCKS5] TCP proxy connection failed", "client", clientConn.RemoteAddr(), "err", err)
	}
}

func (c *Inbound) handleTCP(ctx context.Context, clientConn net.Conn, targetAddr *core.Address, initialPayload []byte) error {
	if err := SendResponse(clientConn, ""); err != nil {
		return fmt.Errorf("send response failed: %w", err)
	}

	outConn, err := c.Outbound.Dial(ctx, targetAddr)
	if err != nil {
		return fmt.Errorf("create outbound connection failed: %w", err)
	}
	defer outConn.Close()

	if len(initialPayload) > 0 {
		if _, err := outConn.Write(initialPayload); err != nil {
			return fmt.Errorf("write initial payload failed: %w", err)
		}
	}

	slog.Debug("[SOCKS5] TCP proxy connection established", "client", clientConn.RemoteAddr(), "target", targetAddr)

	if err = ignoreExpectedErrors(core.Relay(ctx, clientConn, outConn)); err != nil {
		return fmt.Errorf("TCP relay failed: %w", err)
	}

	slog.Debug("[SOCKS5] TCP proxy connection disconnected", "client", clientConn.RemoteAddr(), "target", targetAddr)
	return nil
}

func (c *Inbound) handleUDP(ctx context.Context, clientConn net.Conn) error {
	if err := SendResponse(clientConn, c.ListenAddr); err != nil {
		return fmt.Errorf("send response failed: %w", err)
	}

	ssOut, ok := c.Outbound.(*shadowsocks.Outbound)
	if !ok {
		return fmt.Errorf("UDP is not supported for this outbound type")
	}

	udpRelay, err := shadowsocks.NewUDPRelay(ssOut.Method, ssOut.Key, c.ListenAddr, ssOut.ServerAddr)
	if err != nil {
		return fmt.Errorf("init UDP relay failed: %w", err)
	}

	udpCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		clientConn.Read(make([]byte, 1))
		cancel()
	}()

	slog.Debug("[SOCKS5] UDP relay connection established", "client", clientConn.RemoteAddr(), "server", c.ListenAddr)
	if err = udpRelay.Run(udpCtx); err != nil {
		return fmt.Errorf("UDP relay failed: %w", err)
	}
	slog.Debug("[SOCKS5] UDP relay connection closed", "client", clientConn.RemoteAddr(), "server", c.ListenAddr)
	return nil
}

func ignoreExpectedErrors(err error) error {
	if errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) {
		return nil
	}
	return err
}
