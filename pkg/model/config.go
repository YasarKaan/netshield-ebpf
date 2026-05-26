package model

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Interface string         `yaml:"interface"`
	GeoIPPath string         `yaml:"geoip_path"`
	XDP       XDPConfig      `yaml:"xdp"`
	Analyzer  AnalyzerConfig `yaml:"analyzer"`
	Notifier  NotifierConfig `yaml:"notifier"`
	API       APIConfig      `yaml:"api"`
	Log       LogConfig      `yaml:"log"`
}

type XDPConfig struct {
	Mode string `yaml:"mode"` // native, skb, offload
}

type AnalyzerConfig struct {
	RateLimit      RateLimitConfig `yaml:"rate_limit"`
	PortScan       PortScanConfig  `yaml:"port_scan"`
	CoarsePPSLimit int             `yaml:"coarse_pps_limit"`
	SampleEveryN   int             `yaml:"sample_every_n"`
}

type RateLimitConfig struct {
	PPS           int `yaml:"pps"`
	WindowSeconds int `yaml:"window_seconds"`
}

type PortScanConfig struct {
	DistinctPorts int    `yaml:"distinct_ports"`
	Window        string `yaml:"window"` // e.g. "10s"
}

type NotifierConfig struct {
	DebounceWindow string        `yaml:"debounce_window"` // e.g. "10s"
	Slack          WebhookConfig `yaml:"slack"`
	Discord        WebhookConfig `yaml:"discord"`
}

type WebhookConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

type APIConfig struct {
	ListenAddr string     `yaml:"listen_addr"`
	Auth       AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Interface) == "" {
		return fmt.Errorf("interface must not be empty")
	}

	switch c.XDP.Mode {
	case "", "native", "generic", "skb", "offload":
	default:
		return fmt.Errorf("invalid xdp.mode %q", c.XDP.Mode)
	}

	if c.Analyzer.RateLimit.PPS <= 0 {
		return fmt.Errorf("analyzer.rate_limit.pps must be > 0")
	}
	if c.Analyzer.RateLimit.WindowSeconds <= 0 {
		return fmt.Errorf("analyzer.rate_limit.window_seconds must be > 0")
	}
	if c.Analyzer.PortScan.DistinctPorts <= 0 {
		return fmt.Errorf("analyzer.port_scan.distinct_ports must be > 0")
	}
	if _, err := time.ParseDuration(c.Analyzer.PortScan.Window); err != nil {
		return fmt.Errorf("invalid analyzer.port_scan.window: %w", err)
	}
	if c.Analyzer.CoarsePPSLimit < 0 {
		return fmt.Errorf("analyzer.coarse_pps_limit must be >= 0")
	}
	if c.Analyzer.SampleEveryN <= 0 {
		return fmt.Errorf("analyzer.sample_every_n must be > 0")
	}
	if _, err := time.ParseDuration(c.Notifier.DebounceWindow); err != nil {
		return fmt.Errorf("invalid notifier.debounce_window: %w", err)
	}
	if strings.TrimSpace(c.API.ListenAddr) == "" {
		return fmt.Errorf("api.listen_addr must not be empty")
	}
	if c.API.Auth.Enabled && strings.TrimSpace(c.API.Auth.Token) == "" {
		return fmt.Errorf("api.auth.token must not be empty when auth is enabled")
	}
	if err := validateWebhookConfig("notifier.slack", c.Notifier.Slack); err != nil {
		return err
	}
	if err := validateWebhookConfig("notifier.discord", c.Notifier.Discord); err != nil {
		return err
	}

	return nil
}

func validateWebhookConfig(name string, cfg WebhookConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.WebhookURL) == "" {
		return fmt.Errorf("%s.webhook_url must not be empty when enabled", name)
	}
	if _, err := url.ParseRequestURI(cfg.WebhookURL); err != nil {
		return fmt.Errorf("invalid %s.webhook_url: %w", name, err)
	}
	return nil
}
