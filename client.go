package kitsune

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"os"
	
	"github.com/aomori446/kage/config"
	"github.com/aomori446/kage/handler"
	"github.com/aomori446/kage/shadowsocks"
	"github.com/aomori446/kage/socks5"
)

func ServeTCP(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	lnAddr, err := net.ResolveTCPAddr("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp", lnAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	logger.Info("TCP client started", "listenAddr", cfg.ListenAddr)
	
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				logger.Info("TCP client closed", "cause", context.Cause(ctx))
				return nil
			}
			return err
		}
		
		lg := logger.With("clientAddr", conn.RemoteAddr().String(), "serverAddr", cfg.ServerAddr)
		if cfg.Protocol == config.ProtocolSocks5 {
			lg.Debug("new client connection accepted")
		} else if cfg.Protocol == config.ProtocolTunnel {
			lg.Debug("new client connection accepted", "forwardAddr", cfg.ForwardAddr)
		}
		
		go func(ctx context.Context, conn net.Conn) {
			if err := handleConnection(ctx, conn, lg, cfg); err != nil {
				lg.Error("handle connection failed", "err", err, "clientAddr", conn.RemoteAddr().String())
			}
		}(ctx, conn)
	}
	
}

func handleConnection(ctx context.Context, conn net.Conn, logger *slog.Logger, cfg *config.Config) error {
	defer conn.Close()
	
	foAddr, err := socks5.ParseAddrFromString(cfg.ForwardAddr)
	if err != nil {
		return err
	}
	handshaker, err := handler.NewTCPHandshaker(cfg.Protocol, foAddr)
	if err != nil {
		return err
	}
	
	targetAddr, err := handshaker.Handshake(ctx, conn)
	if err != nil {
		return err
	}
	
	logger.Debug("client handshake succeeded", "targetAddr", targetAddr.String())
	
	var initialPayload []byte
	if cfg.FastOpen {
		payload, err := shadowsocks.WaitForInitialPayload(conn)
		if err != nil {
			return err
		}
		initialPayload = payload
	}
	
	seAddr, err := net.ResolveTCPAddr("tcp", cfg.ServerAddr)
	if err != nil {
		return err
	}
	
	key, err := base64.StdEncoding.DecodeString(cfg.Password)
	if err != nil {
		return err
	}
	
	stc, err := shadowsocks.NewShadowTCPConn(ctx, seAddr, key, cfg.CipherMethod, logger)
	if err != nil {
		return err
	}
	
	stc.Stream(conn, targetAddr, initialPayload)
	return nil
}

func ServeUDP(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	logger.Info("UDP client started", "listenAddr", cfg.ListenAddr)
	
	foAddr, err := socks5.ParseAddrFromString(cfg.ForwardAddr)
	if err != nil {
		return err
	}
	
	ph, err := handler.NewUDPPacketHandler(cfg.Protocol, foAddr)
	if err != nil {
		return err
	}
	
	seAddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return err
	}
	
	lnAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	
	key, err := base64.StdEncoding.DecodeString(cfg.Password)
	if err != nil {
		return err
	}
	
	r, err := shadowsocks.NewRelayer(key, cfg.CipherMethod, lnAddr, seAddr, ph, logger)
	if err != nil {
		return err
	}
	
	return r.Relay(ctx)
}

func RunClient(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	switch cfg.Mode {
	case config.ModeTCP:
		return ServeTCP(ctx, logger, cfg)
	case config.ModeUDP:
		return ServeUDP(ctx, logger, cfg)
	default:
		return config.ErrUnknownMode
	}
}
