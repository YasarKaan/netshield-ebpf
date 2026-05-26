package loader

import (
	"testing"

	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

func TestLoaderMockMode(t *testing.T) {
	cfg := &model.Config{
		Interface: "lo0",
		XDP: model.XDPConfig{
			Mode: "generic",
		},
		Analyzer: model.AnalyzerConfig{
			CoarsePPSLimit: 1000,
			SampleEveryN:   1,
		},
	}

	ld, handles, err := New(cfg)
	if err != nil {
		t.Fatalf("expected no error in loader mock initialization, got: %v", err)
	}

	if ld == nil {
		t.Fatal("expected loader to be non-nil")
	}

	if handles == nil {
		t.Fatal("expected handles to be non-nil")
	}

	if err := ld.Close(); err != nil {
		t.Fatalf("expected no error on loader Close, got: %v", err)
	}
}
