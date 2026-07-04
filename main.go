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
)

type Inbound interface {
	Run(ctx context.Context) error
}

func main() {
	configPath := flag.String("c", "config.json", "Config file path")
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

	slog.Info("kage started", "inbounds", len(cfg.Inbounds), "method", cfg.Method)

	var wg sync.WaitGroup
	for _, in := range cfg.Inbounds {
		wg.Add(1)

		go func(in InboundConfig) {
			defer wg.Done()

			var r Inbound
			switch in.Type {
			case "socks5":
				r = &socks5.Inbound{
					ListenAddr: in.ListenAddr,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					Key:        cfg.Key,
					FastOpen:   in.FastOpen,
					UDP:        in.UDP,
				}
			case "tunnel":
				r = &tunnel.Inbound{
					ListenAddr: in.ListenAddr,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					TargetAddr: in.Target,
					Key:        cfg.Key,
				}
			case "http":
				r = &http.Inbound{
					ListenAddr: in.ListenAddr,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					Key:        cfg.Key,
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
