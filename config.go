package main

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// ChainConfig defines the configuration for a specific blockchain node connection.
type ChainConfig struct {
	Name             string `toml:"name"`
	PrefixRootDomain string `toml:"prefix_root_domain"`
	Host             string `toml:"host"`
	TLSPath          string `toml:"tls_path"`
	MacaroonPath     string `toml:"macaroon_path"`
}

// Config defines the global configuration for the application.
type Config struct {
	// Global settings
	ListenAddrUDP   string `toml:"listen_udp"`
	ListenAddrTCP   string `toml:"listen_tcp"`
	RootDomain      string `toml:"root_domain"`
	AuthoritativeIP string `toml:"root_ip"`
	PollInterval    int    `toml:"poll_interval"`
	Debug           bool   `toml:"debug"`
	NumResults      int    `toml:"results"`

	// Chains
	Flokicoin ChainConfig   `toml:"flokicoin"`
	AltChains []ChainConfig `toml:"alt_chains"`
}

// loadConfig reads and parses the configuration from the specified file path.
// It applies default values where appropriate.
func loadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	cfg := &Config{
		// Set defaults
		ListenAddrUDP:   "0.0.0.0:53",
		ListenAddrTCP:   "0.0.0.0:53",
		RootDomain:      "nodes.lightning.directory",
		AuthoritativeIP: "127.0.0.1",
		PollInterval:    600,
		Debug:           false,
		NumResults:      25,
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %v", err)
	}

	return cfg, nil
}
