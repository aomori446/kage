package tunnel

import (
	"context"
	"errors"
	"kage/core"
	"kage/shadowsocks"
	"log/slog"
	"net"
	"time"
)

type Client struct {
	ListenAddr string
	ServerAddr string
	Method     string
	TargetAddr string
	
	Key []byte
}

func (c *Client) Run(ctx context.Context) error {
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

func (c *Client) handle(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	
	serverConn, err := net.DialTimeout("tcp", c.ServerAddr, time.Second*3)
	if err != nil {
		return err
	}
	defer serverConn.Close()
	
	targetAddr, err := core.ParseAddress(c.TargetAddr)
	if err != nil {
		return err
	}
	
	slog.Debug("Tunnel connecting", "remote", clientConn.RemoteAddr(), "target", targetAddr)
	
	shadowConn, err := shadowsocks.NewConn(serverConn, c.Method, c.Key, targetAddr, nil)
	if err != nil {
		return err
	}
	defer shadowConn.Close()
	
	core.TCPRelay(ctx, clientConn, shadowConn)
	return nil
}
