package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/aomori446/kage/core"
	"github.com/aomori446/kage/outbound"
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
	lAddr, err := net.ResolveUDPAddr("udp", c.ListenAddr)
	if err != nil {
		return err
	}
	// Bind to a random port on the same IP
	socks5UDPConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr.IP, Port: 0})
	if err != nil {
		return fmt.Errorf("bind SOCKS5 UDP port failed: %w", err)
	}
	defer socks5UDPConn.Close()

	// Send UDP port info to SOCKS5 client
	if err := SendResponse(clientConn, socks5UDPConn.LocalAddr().String()); err != nil {
		return fmt.Errorf("send response failed: %w", err)
	}

	udpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Close SOCKS5 UDP if client TCP connection terminates
	go func() {
		buf := make([]byte, 1)
		clientConn.Read(buf)
		cancel()
	}()

	outUDP, err := c.Outbound.ListenUDP(udpCtx)
	if err != nil {
		return fmt.Errorf("init outbound UDP failed: %w", err)
	}
	defer outUDP.Close()

	var clientAddr net.Addr
	var clientAddrMu sync.Mutex

	// Client -> Outbound
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-udpCtx.Done():
				return
			default:
			}

			socks5UDPConn.SetReadDeadline(time.Now().Add(time.Second))
			n, fromAddr, err := socks5UDPConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			clientAddrMu.Lock()
			clientAddr = fromAddr
			clientAddrMu.Unlock()

			// Parse SOCKS5 Datagram
			targetAddr, payload, err := ParseDatagram(buf[:n])
			if err != nil {
				slog.Debug("[SOCKS5] parse UDP datagram failed", "err", err)
				continue
			}

			// Forward payload to outbound
			_, err = outUDP.WriteTo(payload, targetAddr)
			if err != nil {
				slog.Debug("[SOCKS5] write to outbound UDP failed", "err", err)
				continue
			}
		}
	}()

	// Outbound -> Client
	buf := make([]byte, 65535)
	for {
		select {
		case <-udpCtx.Done():
			return nil
		default:
		}

		n, sourceAddr, err := outUDP.ReadFrom(buf)
		if err != nil {
			return err
		}

		clientAddrMu.Lock()
		cAddr := clientAddr
		clientAddrMu.Unlock()

		if cAddr == nil {
			continue
		}

		// Pack as SOCKS5 Datagram
		packed := PackDatagram(sourceAddr, buf[:n])

		// Send back to client
		_, err = socks5UDPConn.WriteTo(packed, cAddr)
		if err != nil {
			slog.Debug("[SOCKS5] write to client UDP failed", "err", err)
			continue
		}
	}
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
