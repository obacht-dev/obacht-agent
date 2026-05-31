// Package config loads /etc/obacht/agent.yml (or a path passed via flag/env)
// into a typed struct. Layout intentionally matches v1 to keep the bootstrap
// migration trivial: same file paths, same keys, additive only.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk shape of agent.yml.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Registry RegistryConfig `yaml:"registry"`
	Paths    PathsConfig    `yaml:"paths"`
	Ingress  IngressConfig  `yaml:"ingress"`
}

type ServerConfig struct {
	URL       string `yaml:"url"`       // e.g. https://api.eu.obacht.dev
	DeviceID  string `yaml:"deviceId"`  // uuid issued by backend
	AuthToken string `yaml:"authToken"` // device JWT (or one-time install token)
}

type RegistryConfig struct {
	URL string `yaml:"url"` // e.g. https://registry.eu.obacht.dev
}

type PathsConfig struct {
	StateDB     string `yaml:"stateDb"`     // SQLite SSOT location
	Socket      string `yaml:"socket"`      // unix socket for IPC + agentctl
	CaddyData   string `yaml:"caddyData"`   // /var/lib/obacht/caddy/data
	CaddyConfig string `yaml:"caddyConfig"` // /var/lib/obacht/caddy/config
	AuditLog    string `yaml:"auditLog"`    // append-only JSONL audit log
	ComposeRoot string `yaml:"composeRoot"` // workspace root for compose-runtime instances
}

type IngressConfig struct {
	Disabled bool   `yaml:"disabled"` // skip caddy management entirely
	Image    string `yaml:"image"`    // override caddy image (default caddy:2-alpine)
	Network  string `yaml:"network"`  // docker network name (default obacht-edge)
}

// DefaultPath returns the canonical config location for the host OS.
func DefaultPath() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", "obacht", "agent.yml")
		}
	}
	return "/etc/obacht/agent.yml"
}

// DefaultStateDB returns the canonical SQLite path for the host OS.
func DefaultStateDB() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", "obacht", "agent.db")
		}
	}
	return "/var/lib/obacht/agent.db"
}

// DefaultSocket returns the canonical unix-socket path for the host OS.
func DefaultSocket() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", "obacht", "agent-v2.sock")
		}
	}
	return "/run/obacht/agent-v2.sock"
}

// DefaultAuditLog returns the canonical audit log path for the host OS.
func DefaultAuditLog() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", "obacht", "audit.log")
		}
	}
	return "/var/log/obacht/audit.log"
}

// DefaultComposeRoot returns the workspace root for compose-runtime
// instances (one subdir per instance).
func DefaultComposeRoot() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", "obacht", "compose")
		}
	}
	return "/var/lib/obacht/compose"
}

// Load reads a config file. Returns a zero-value config + nil error if the
// file does not exist (caller may decide whether that is fatal).
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c := &Config{}
			c.applyDefaults()
			return c, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Paths.StateDB == "" {
		c.Paths.StateDB = DefaultStateDB()
	}
	if c.Paths.Socket == "" {
		c.Paths.Socket = DefaultSocket()
	}
	if c.Paths.CaddyData == "" {
		c.Paths.CaddyData = "/var/lib/obacht/caddy/data"
	}
	if c.Paths.CaddyConfig == "" {
		c.Paths.CaddyConfig = "/var/lib/obacht/caddy/config"
	}
	if c.Paths.AuditLog == "" {
		c.Paths.AuditLog = DefaultAuditLog()
	}
	if c.Paths.ComposeRoot == "" {
		c.Paths.ComposeRoot = DefaultComposeRoot()
	}
	if c.Ingress.Image == "" {
		c.Ingress.Image = "caddy:2-alpine"
	}
	if c.Ingress.Network == "" {
		c.Ingress.Network = "obacht-edge"
	}
}
