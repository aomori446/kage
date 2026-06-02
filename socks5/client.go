package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"kage/core"
	"kage/shadowsocks"
	"log/slog"
	"net"
	"syscall"
	"time"
)

type Client struct {
	ListenAddr string
	ServerAddr string
	Method     string
	Key        []byte
	FastOpen   bool
	
	UDP bool
}

func (c *Client) Run(ctx context.Context) error {
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

func (c *Client) handleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	
	handshakeRes, err := Handshake(clientConn, c.FastOpen)
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

func (c *Client) handleTCP(ctx context.Context, clientConn net.Conn, targetAddr *core.Address, initialPayload []byte) error {
	if err := SendResponse(clientConn, ""); err != nil {
		return fmt.Errorf("send response failed: %w", err)
	}
	
	serverConn, err := net.DialTimeout("tcp", c.ServerAddr, time.Second*3)
	if err != nil {
		return fmt.Errorf("dial server for %v failed: %w", targetAddr, err)
	}
	defer serverConn.Close()
	
	shadowConn, err := shadowsocks.NewConn(serverConn, c.Method, c.Key, targetAddr, initialPayload)
	if err != nil {
		return fmt.Errorf("create shadow connection failed: %w", err)
	}
	defer shadowConn.Close()
	
	if _, err = shadowConn.Write(nil); err != nil {
		return fmt.Errorf("send handshake to server header failed: %w", err)
	}
	
	slog.Debug("[SOCKS5] TCP proxy connection established", "client", clientConn.RemoteAddr(), "server", serverConn.RemoteAddr(), "target", targetAddr)
	err = core.TCPRelay(ctx, clientConn, shadowConn)
	err = ignoreExpectedErrors(err)
	if err != nil {
		return fmt.Errorf("TCP relay failed: %w", err)
	}
	slog.Debug("[SOCKS5] TCP proxy connection disconnected", "client", clientConn.RemoteAddr(), "server", serverConn.RemoteAddr(), "target", targetAddr)
	return nil
}

func (c *Client) handleUDP(ctx context.Context, clientConn net.Conn) error {
	if err := SendResponse(clientConn, c.ListenAddr); err != nil {
		return fmt.Errorf("send response failed: %w", err)
	}
	
	udpClient, err := shadowsocks.NewUDPClient(c.Method, c.Key, c.ListenAddr, c.ServerAddr)
	if err != nil {
		return fmt.Errorf("init UDP client failed: %w", err)
	}
	
	udpCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		clientConn.Read(make([]byte, 1))
		cancel()
	}()
	
	slog.Debug("[SOCKS5] UDP relay connection established", "client", clientConn.RemoteAddr(), "server", c.ListenAddr)
	if err = udpClient.Run(udpCtx); err != nil {
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
