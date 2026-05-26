package analyzer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type MockBlocker struct {
	mu      sync.Mutex
	blocked map[string]time.Duration
}

func (m *MockBlocker) BlockIP(ctx context.Context, ip string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocked[ip] = duration
	return nil
}

type MockNotifier struct {
	mu       sync.Mutex
	notified map[string]string
}

func (m *MockNotifier) NotifyAttack(ctx context.Context, ip string, reason string, rate float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notified[ip] = reason
	return nil
}

func TestDDoSDetection(t *testing.T) {
	in := make(chan model.PacketEvent, 100)
	out := make(chan model.BlockDecision, 100)

	cfg := model.AnalyzerConfig{
		RateLimit: model.RateLimitConfig{
			PPS:           10,
			WindowSeconds: 1,
		},
		PortScan: model.PortScanConfig{
			DistinctPorts: 5,
			Window:        "1s",
		},
	}

	anz := New(cfg, in, out)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go anz.Run(ctx)

	attackerIP := "198.51.100.5"
	ip := net.ParseIP(attackerIP)
	now := time.Now()

	for i := 0; i < 11; i++ {
		in <- model.PacketEvent{
			Timestamp: now,
			SrcIP:     ip,
			DstIP:     net.ParseIP("192.168.1.10"),
			DstPort:   80,
			Protocol:  6,
		}
	}

	select {
	case decision := <-out:
		if decision.IP.String() != attackerIP {
			t.Errorf("expected IP %s, got %s", attackerIP, decision.IP.String())
		}
		if decision.Reason != model.ReasonRateLimit {
			t.Errorf("expected reason %v, got %v", model.ReasonRateLimit, decision.Reason)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for DDoS block decision")
	}
}

func TestPortScanDetection(t *testing.T) {
	in := make(chan model.PacketEvent, 100)
	out := make(chan model.BlockDecision, 100)

	cfg := model.AnalyzerConfig{
		RateLimit: model.RateLimitConfig{
			PPS:           100,
			WindowSeconds: 1,
		},
		PortScan: model.PortScanConfig{
			DistinctPorts: 5,
			Window:        "1s",
		},
	}

	anz := New(cfg, in, out)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go anz.Run(ctx)

	scannerIP := "203.0.113.88"
	ip := net.ParseIP(scannerIP)
	now := time.Now()

	for port := uint16(1); port <= 6; port++ {
		in <- model.PacketEvent{
			Timestamp: now,
			SrcIP:     ip,
			DstIP:     net.ParseIP("192.168.1.10"),
			DstPort:   port,
			Protocol:  6,
		}
	}

	select {
	case decision := <-out:
		if decision.IP.String() != scannerIP {
			t.Errorf("expected IP %s, got %s", scannerIP, decision.IP.String())
		}
		if decision.Reason != model.ReasonPortScan {
			t.Errorf("expected reason %v, got %v", model.ReasonPortScan, decision.Reason)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for Port Scan block decision")
	}
}

func TestPrivateIPExclusion(t *testing.T) {
	in := make(chan model.PacketEvent, 100)
	out := make(chan model.BlockDecision, 100)

	cfg := model.AnalyzerConfig{
		RateLimit: model.RateLimitConfig{
			PPS:           5,
			WindowSeconds: 1,
		},
		PortScan: model.PortScanConfig{
			DistinctPorts: 2,
			Window:        "1s",
		},
	}

	anz := New(cfg, in, out)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go anz.Run(ctx)

	privateIP := "10.0.0.5"
	ip := net.ParseIP(privateIP)
	now := time.Now()

	for i := 0; i < 10; i++ {
		in <- model.PacketEvent{
			Timestamp: now,
			SrcIP:     ip,
			DstIP:     net.ParseIP("10.0.0.1"),
			DstPort:   80,
			Protocol:  6,
		}
	}

	select {
	case decision := <-out:
		t.Fatalf("unexpected block decision for private IP: %v", decision)
	case <-time.After(100 * time.Millisecond):
		// Success
	}
}

func TestAnalyzerDeduplicatesRecentDecisions(t *testing.T) {
	in := make(chan model.PacketEvent, 100)
	out := make(chan model.BlockDecision, 100)

	cfg := model.AnalyzerConfig{
		RateLimit: model.RateLimitConfig{
			PPS:           1,
			WindowSeconds: 1,
		},
		PortScan: model.PortScanConfig{
			DistinctPorts: 5,
			Window:        "1s",
		},
	}

	anz := New(cfg, in, out)
	defer anz.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go anz.Run(ctx)

	ip := net.ParseIP("198.51.100.55")
	now := time.Now()

	in <- model.PacketEvent{Timestamp: now, SrcIP: ip, DstIP: net.ParseIP("192.168.1.10"), DstPort: 80, Protocol: 6}
	in <- model.PacketEvent{Timestamp: now, SrcIP: ip, DstIP: net.ParseIP("192.168.1.10"), DstPort: 80, Protocol: 6}
	in <- model.PacketEvent{Timestamp: now, SrcIP: ip, DstIP: net.ParseIP("192.168.1.10"), DstPort: 80, Protocol: 6}

	select {
	case <-out:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for first block decision")
	}

	select {
	case decision := <-out:
		t.Fatalf("unexpected duplicate block decision: %+v", decision)
	case <-time.After(150 * time.Millisecond):
	}
}
