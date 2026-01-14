package kage

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
	
	"github.com/aomori446/kage/config"
	"github.com/aomori446/kage/handler"
	"github.com/aomori446/kage/shadowsocks"
	"github.com/aomori446/kage/socks5"
)

type Client interface {
	Serve(ctx context.Context) error
}

func NewClient(cfg *config.Config, logger *slog.Logger) (Client, error) {
	if logger == nil {
		logger = slog.Default()
	}
	switch cfg.Protocol {
	case config.ProtocolSocks:
		return NewSocks5Client(cfg, logger)
	case config.ProtocolTunnel:
		return NewTunnelClient(cfg, logger)
	default:
		return nil, config.ErrUnknownProtocol
	}
}

// --- Socks5 Client ---

type Socks5Client struct {
	cfg    *config.Config
	logger *slog.Logger
}

func NewSocks5Client(cfg *config.Config, logger *slog.Logger) (*Socks5Client, error) {
	return &Socks5Client{
		cfg:    cfg,
		logger: logger.With("protocol", "socks", "mode", cfg.Mode),
	}, nil
}

func (c *Socks5Client) Serve(ctx context.Context) error {
	switch c.cfg.Mode {
	case config.ModeTCPOnly:
		handshaker := &handler.TCPSocks5Handshaker{}
		proxy, err := newTCPProxy(c.cfg, handshaker)
		if err != nil {
			return err
		}
		return proxy.Serve(ctx, c.logger)
	default:
		return config.ErrUnknownMode
	}
}

// --- Tunnel Client ---

type TunnelClient struct {
	cfg    *config.Config
	logger *slog.Logger
}

func NewTunnelClient(cfg *config.Config, logger *slog.Logger) (*TunnelClient, error) {
	if cfg.ForwardAddr == "" {
		return nil, errors.New("forward address is required for tunnel mode")
	}
	return &TunnelClient{
		cfg:    cfg,
		logger: logger.With("protocol", "tunnel", "mode", cfg.Mode),
	}, nil
}

func (c *TunnelClient) Serve(ctx context.Context) error {
	foAddr, err := socks5.ParseAddrFromString(c.cfg.GetForwardAddr())
	if err != nil {
		return fmt.Errorf("invalid forward address: %w", err)
	}

	switch c.cfg.Mode {
	case config.ModeTCPOnly:
		handshaker := &handler.TCPTunnelHandshaker{ForwardAddr: foAddr}
		proxy, err := newTCPProxy(c.cfg, handshaker)
		if err != nil {
			return err
		}
		return proxy.Serve(ctx, c.logger)
	default:
		return config.ErrUnknownMode
	}
}

// --- TCP Proxy ---

type tcpProxy struct {
	ln           *net.TCPListener
	handshaker   handler.TCPHandshaker
	fastOpen     bool
	serverAddr   *net.TCPAddr
	key          []byte
	cipherMethod config.CipherMethod
}

func newTCPProxy(cfg *config.Config, handshaker handler.TCPHandshaker) (*tcpProxy, error) {
	lnAddr, err := net.ResolveTCPAddr("tcp", cfg.GetLocalAddr())
	if err != nil {
		return nil, err
	}

	ln, err := net.ListenTCP("tcp", lnAddr)
	if err != nil {
		return nil, err
	}

	serverAddr, err := net.ResolveTCPAddr("tcp", cfg.GetServerAddr())
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(cfg.Password)
	if err != nil {
		return nil, err
	}

	return &tcpProxy{
		ln:           ln,
		handshaker:   handshaker,
		fastOpen:     cfg.FastOpen,
		serverAddr:   serverAddr,
		key:          key,
		cipherMethod: cfg.Method,
	}, nil
}
func (c *tcpProxy) Serve(ctx context.Context, logger *slog.Logger) error {
	defer c.ln.Close()
	
	go func() {
		<-ctx.Done()
		_ = c.ln.Close()
	}()
	
	logger.Info("TCP client started", "listenAddr", c.ln.Addr().String())
	
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				logger.Info("TCP client closed", "cause", context.Cause(ctx))
				return nil
			}
			return err
		}
		
		lg := logger.With("clientAddr", conn.RemoteAddr().String(), "serverAddr", c.serverAddr.String())
		
		go func(ctx context.Context, conn net.Conn) {
			if err := c.handleConnection(ctx, conn, lg); err != nil {
				lg.Error("handle connection failed", "err", err, "clientAddr", conn.RemoteAddr().String())
			}
		}(ctx, conn)
	}
}

func (c *tcpProxy) handleConnection(ctx context.Context, conn net.Conn, logger *slog.Logger) error {
	defer conn.Close()
	
	targetAddr, err := c.handshaker.Handshake(conn, shadowsocks.HandshakeTimeout)
	if err != nil {
		return err
	}
	
	logger = logger.With("targetAddr", targetAddr.String())
	logger.Debug("client handshake succeeded")
	
	var initialPayload []byte
	if c.fastOpen {
		payload, err := shadowsocks.ReadInitialPayload(conn, 50*time.Millisecond)
		if err != nil {
			return err
		}
		initialPayload = payload
	}
	
	stc, err := shadowsocks.NewShadowTCPConn(c.serverAddr, c.key, c.cipherMethod)
	if err != nil {
		return err
	}
	
	stc.Stream(ctx, conn, targetAddr, initialPayload, logger)
	return nil
}