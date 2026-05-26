package model

import "testing"

func TestConfigValidate(t *testing.T) {
	valid := &Config{
		Interface: "eth0",
		XDP:       XDPConfig{Mode: "generic"},
		Analyzer: AnalyzerConfig{
			RateLimit:      RateLimitConfig{PPS: 1000, WindowSeconds: 5},
			PortScan:       PortScanConfig{DistinctPorts: 20, Window: "10s"},
			CoarsePPSLimit: 5000,
			SampleEveryN:   1,
		},
		Notifier: NotifierConfig{
			DebounceWindow: "10s",
		},
		API: APIConfig{
			ListenAddr: ":8080",
			Auth:       AuthConfig{Enabled: true, Token: "secret"},
		},
		Log: LogConfig{Level: "info", Format: "json"},
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidateRejectsInvalidFields(t *testing.T) {
	cfg := &Config{
		Interface: "",
		XDP:       XDPConfig{Mode: "broken"},
		Analyzer: AnalyzerConfig{
			RateLimit:      RateLimitConfig{PPS: 0, WindowSeconds: 0},
			PortScan:       PortScanConfig{DistinctPorts: 0, Window: "bad"},
			CoarsePPSLimit: -1,
			SampleEveryN:   0,
		},
		Notifier: NotifierConfig{
			DebounceWindow: "bad",
		},
		API: APIConfig{
			ListenAddr: "",
			Auth:       AuthConfig{Enabled: true, Token: ""},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid config to fail validation")
	}
}
