package main

import (
	"context"
	"flag"
	"kage/internal/config"
	"kage/internal/logger"
	"kage/pkg/proxy/inbound"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	configPath := flag.String("c", "config.json", "Config file path")
	flag.Parse()
	
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	
	logger.Init(cfg.LogLevel)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("shutting down...")
		cancel()
	}()
	
	var wg sync.WaitGroup
	for _, in := range cfg.Inbounds {
		wg.Add(1)
		
		go func(in config.InboundConfig) {
			defer wg.Done()
			
			var err error
			switch in.Type {
			case "socks5":
				s := &inbound.Socks5{
					ListenAddr: in.Listen,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					Key:        cfg.Key,
					FastOpen:   in.FastOpen,
				}
				err = s.Listen(ctx)
			case "tunnel":
				t := &inbound.Tunnel{
					ListenAddr: in.Listen,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					TargetAddr: in.Target,
					Key:        cfg.Key,
				}
				err = t.Listen(ctx)
			case "http":
				h := &inbound.HttpProxy{
					ListenAddr: in.Listen,
					ServerAddr: cfg.Server,
					Method:     cfg.Method,
					Key:        cfg.Key,
				}
				err = h.Listen(ctx)
			default:
				slog.Warn("unknown inbound type", "type", in.Type)
				return
			}
			
			if err != nil {
				slog.Error("inbound failed", "type", in.Type, "listen", in.Listen, "error", err)
			}
		}(in)
	}
	
	slog.Info("kage started", "inbounds", len(cfg.Inbounds), "method", cfg.Method)
	wg.Wait()
	slog.Info("kage exit")
}
