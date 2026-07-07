// Package config manages the GophKeeper client configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config holds client runtime settings persisted in ~/.gophkeeper/config.yaml.
type Config struct {
	ServerAddr   string `mapstructure:"server_addr"`
	TLSCertPath  string `mapstructure:"tls_cert_path"`
	AccessToken  string `mapstructure:"access_token"`
	RefreshToken string `mapstructure:"refresh_token"`
	VaultPath    string `mapstructure:"vault_path"`
	KeyfilePath  string `mapstructure:"keyfile_path"`
	Username     string `mapstructure:"username"`
}

// dir returns the ~/.gophkeeper directory path.
func dir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gophkeeper")
}

// Load reads the client config file; returns defaults if file does not exist.
func Load() (*Config, error) {
	d := dir()
	_ = os.MkdirAll(d, 0700)

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(d)

	v.SetDefault("server_addr", "localhost:50051")
	v.SetDefault("vault_path", filepath.Join(d, "vault.gkdb"))

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

// Save writes the config back to disk.
func Save(cfg *Config) error {
	d := dir()
	_ = os.MkdirAll(d, 0700)

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(d)

	v.Set("server_addr", cfg.ServerAddr)
	v.Set("tls_cert_path", cfg.TLSCertPath)
	v.Set("access_token", cfg.AccessToken)
	v.Set("refresh_token", cfg.RefreshToken)
	v.Set("vault_path", cfg.VaultPath)
	v.Set("keyfile_path", cfg.KeyfilePath)
	v.Set("username", cfg.Username)

	path := filepath.Join(d, "config.yaml")
	if err := v.WriteConfigAs(path); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return os.Chmod(path, 0600)
}
