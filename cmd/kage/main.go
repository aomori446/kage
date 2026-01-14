package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	
	"github.com/aomori446/kage"
	"github.com/aomori446/kage/config"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "c", "", "path to config file")
	flag.Parse()
	
	if configPath == "" {
		fmt.Println("Usage: kage -c config.json")
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	
	client, err := kage.NewClient(cfg, logger)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Serve(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}
