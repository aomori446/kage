package inbound

import (
	"context"
	"kage/pkg/core"
	"kage/pkg/crypto/shadowsocks"
	"kage/pkg/proxy/outbound"
	"kage/pkg/transport/tcp"
	"log/slog"
	"net"
	"time"
)

type Tunnel struct {
	ListenAddr string
	ServerAddr string
	Method     string
	TargetAddr string

	Key []byte
}

func (t *Tunnel) Listen(ctx context.Context) error {
	ln, err := net.Listen("tcp", t.ListenAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	slog.Info("Tunnel inbound listening", "addr", t.ListenAddr, "target", t.TargetAddr)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Error("Tunnel accept error", "error", err)
				continue
			}
		}

		go func() {
			if err := t.handle(ctx, clientConn); err != nil {
				slog.Error("Tunnel handleConn error", "remote", clientConn.RemoteAddr(), "error", err)
			}
		}()
	}
}

func (t *Tunnel) handle(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	serverConn, err := net.DialTimeout("tcp", t.ServerAddr, time.Second*3)
	if err != nil {
		return err
	}

	cipher, err := shadowsocks.NewCipher(t.Method, t.Key)
	if err != nil {
		serverConn.Close()
		return err
	}

	targetAddr, err := core.ParseAddress(t.TargetAddr)
	if err != nil {
		return err
	}

	slog.Debug("Tunnel connecting", "remote", clientConn.RemoteAddr(), "target", targetAddr)

	shadowConn := outbound.NewShadowConn(serverConn, t.Method, cipher, targetAddr, nil)
	defer shadowConn.Close()

	tcp.Relay(ctx, clientConn, shadowConn)
	return nil
}
