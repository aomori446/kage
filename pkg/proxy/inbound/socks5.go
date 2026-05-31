package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"kage/pkg/core"
	sscrypto "kage/pkg/crypto/shadowsocks"
	"kage/pkg/protocol/socks5"
	"kage/pkg/proxy/outbound"
	"kage/pkg/transport/tcp"
	udprelay "kage/pkg/transport/udp"
	"log/slog"
	"net"
	"time"
)

type Socks5 struct {
	ListenAddr string
	ServerAddr string
	Method     string
	Key        []byte
	FastOpen   bool
	UDP        bool
}

func (s *Socks5) Listen(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}
	
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	
	slog.Info("SOCKS5 inbound listening", "addr", s.ListenAddr)
	
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Error("SOCKS5 accept error", "error", err)
				continue
			}
		}
		
		go func() {
			if err := s.handle(ctx, clientConn); err != nil {
				if errors.Is(err, io.EOF) {
					slog.Debug("SOCKS5 client disconnected", "remote", clientConn.RemoteAddr())
				} else {
					slog.Error("SOCKS5 handle error", "remote", clientConn.RemoteAddr(), "error", err)
				}
			}
		}()
	}
}

func (s *Socks5) handle(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	
	handshakeRes, err := socks5.Handshake(clientConn, s.FastOpen)
	if err != nil {
		return err
	}
	
	if handshakeRes.Command == 0x03 {
		if !s.UDP {
			slog.Warn("SOCKS5 UDP Associate rejected: UDP disabled", "client", clientConn.RemoteAddr())
			return nil
		}
		return s.handleUDP(ctx, clientConn)
	}
	
	if err = socks5.SendResponse(clientConn, core.EmptyAddress()); err != nil {
		return err
	}
	
	serverConn, err := net.DialTimeout("tcp", s.ServerAddr, time.Second*5)
	if err != nil {
		return err
	}
	
	slog.Info("SOCKS5 proxying", "client", clientConn.RemoteAddr(), "remote", serverConn.RemoteAddr(), "target", handshakeRes.TargetAddress)
	
	cipher, err := sscrypto.NewCipher(s.Method, s.Key)
	if err != nil {
		serverConn.Close()
		return err
	}
	
	shadowConn := outbound.NewShadowsocks(
		serverConn,
		s.Method,
		cipher,
		handshakeRes.TargetAddress,
		handshakeRes.InitialPayload,
	)
	defer shadowConn.Close()
	
	if _, err = shadowConn.Write(nil); err != nil {
		return err
	}
	
	tcp.Relay(ctx, clientConn, shadowConn)
	return nil
}

func (s *Socks5) handleUDP(ctx context.Context, clientConn net.Conn) error {
	slog.Info("SOCKS5 UDP Associate", "client", clientConn.RemoteAddr())
	
	lnAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return err
	}
	inConn, err := net.ListenUDP("udp", lnAddr)
	if err != nil {
		return err
	}
	defer inConn.Close()
	
	localAddr := inConn.LocalAddr().(*net.UDPAddr)
	host, _, _ := net.SplitHostPort(clientConn.LocalAddr().String())
	associateAddr, err := core.ParseAddress(fmt.Sprintf("%s:%d", host, localAddr.Port))
	if err != nil {
		return err
	}
	
	if err = socks5.SendResponse(clientConn, associateAddr); err != nil {
		return err
	}
	
	ssOut, err := outbound.NewShadowsocksUDP(s.Method, s.Key, s.ServerAddr)
	if err != nil {
		return err
	}
	
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	go func() {
		buf := make([]byte, 1)
		clientConn.Read(buf)
		cancel()
	}()
	
	return udprelay.Relay(relayCtx, inConn, ssOut)
}
