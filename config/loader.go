package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads and parses the configuration from the specified JSON file.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, ErrConfigNotFound
	}

	configFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := json.Unmarshal(configFile, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}
