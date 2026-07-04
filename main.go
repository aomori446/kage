package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/aomori446/kage/inbound/http"
	"github.com/aomori446/kage/inbound/socks5"
	"github.com/aomori446/kage/inbound/tunnel"
	"github.com/aomori446/kage/outbound"
	"github.com/aomori446/kage/outbound/raw"
	"github.com/aomori446/kage/outbound/shadowsocks"
)

type Inbound interface {
	Run(ctx context.Context) error
}

func main() {
	configPath := flag.String("c", "testdata/config.json", "Config file path")
	flag.Parse()

	SetLogLevel("")
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	SetLogLevel(cfg.LogLevel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("shutting down...")
		cancel()
	}()

	slog.Info("kage started", "inbounds", len(cfg.Inbounds), "outbound", cfg.OutboundType)

	var out outbound.Outbound
	switch cfg.OutboundType {
	case "shadowsocks":
		out = shadowsocks.NewOutbound(cfg.Server, cfg.Method, cfg.Key)
	case "raw":
		out = raw.NewOutbound()
	default:
		slog.Error("unknown outbound type", "type", cfg.OutboundType)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for _, in := range cfg.Inbounds {
		wg.Add(1)

		go func(in InboundConfig) {
			defer wg.Done()

			var r Inbound
			switch in.Type {
			case "socks5":
				r = &socks5.Inbound{
					Outbound:   out,
					ListenAddr: in.ListenAddr,
					FastOpen:   in.FastOpen,
					UDP:        in.UDP,
				}
			case "tunnel":
				r = &tunnel.Inbound{
					Outbound:   out,
					ListenAddr: in.ListenAddr,
					TargetAddr: in.Target,
				}
			case "http":
				r = &http.Inbound{
					Outbound:   out,
					ListenAddr: in.ListenAddr,
				}
			default:
				slog.Warn("unknown inbound type", "type", in.Type)
				return
			}

			slog.Info("inbound started", "type", in.Type, "listen", in.ListenAddr)
			err := r.Run(ctx)
			if err == nil {
				slog.Info("inbound stopped", "type", in.Type, "listen", in.ListenAddr)
			} else {
				slog.Error("inbound stopped with error", "type", in.Type, "listen", in.ListenAddr, "err", err)
			}
		}(in)
	}

	wg.Wait()
	slog.Info("kage exit")
}
