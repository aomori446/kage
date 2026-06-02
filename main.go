package main

import (
	"context"
	"flag"
	"kage/http"
	"kage/socks5"
	"kage/tunnel"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

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

			var err error
			switch in.Type {
			case "socks5":
				s := &socks5.Client{
					ListenAddr: in.ListenAddr,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					Key:        cfg.Key,
					FastOpen:   in.FastOpen,
					UDP:        in.UDP,
				}
				slog.Info("[SOCKS5] started", "listen", in.ListenAddr, "server", cfg.Server)
				err = s.Run(ctx)
			case "tunnel":
				t := &tunnel.Client{
					ListenAddr: in.ListenAddr,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					TargetAddr: in.Target,
					Key:        cfg.Key,
				}
				slog.Info("[Tunnel] started", "listen", in.ListenAddr, "server", cfg.Server, "target", in.Target)
				err = t.Run(ctx)
			case "http":
				h := &http.Inbound{
					ListenAddr: in.ListenAddr,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					Key:        cfg.Key,
				}
				slog.Info("[HTTP] started", "listen", in.ListenAddr, "server", cfg.Server)
				err = h.Listen(ctx)
			default:
				slog.Warn("unknown inbound type", "type", in.Type)
				return
			}

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
