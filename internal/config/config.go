package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

type InboundConfig struct {
	Type     string `json:"type"`
	Listen   string `json:"listen"`
	Target   string `json:"target"`
	FastOpen bool   `json:"fast_open"`
}

type Config struct {
	Server   string          `json:"server"`
	Method   string          `json:"method"`
	Password string          `json:"password"`
	LogLevel string          `json:"log_level"` // "debug", "info", "warn", "error"
	Inbounds []InboundConfig `json:"inbounds"`
	
	Key []byte `json:"-"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	
	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	
	key, err := base64.StdEncoding.DecodeString(cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode password: %w", err)
	}
	cfg.Key = key
	
	return &cfg, nil
}
