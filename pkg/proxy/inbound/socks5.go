package inbound

import (
	"context"
	"errors"
	"io"
	sscrypto "kage/pkg/crypto/shadowsocks"
	"kage/pkg/protocol/socks5"
	"kage/pkg/proxy/outbound"
	"kage/pkg/transport/tcp"
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
	
	handshakeRes, err := socks5.Handshake(clientConn, s.ListenAddr, s.FastOpen)
	if err != nil {
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
