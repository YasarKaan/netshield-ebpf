package notifier

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/YasarKaan/go-kit/httputils"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type mockDestination struct {
	mu        sync.Mutex
	calls     int
	decisions []model.BlockDecision
}

func (m *mockDestination) Name() string { return "mock" }
func (m *mockDestination) Send(ctx context.Context, decisions []model.BlockDecision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.decisions = append(m.decisions, decisions...)
	return nil
}

func (m *mockDestination) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *mockDestination) Decisions() []model.BlockDecision {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]model.BlockDecision, len(m.decisions))
	copy(res, m.decisions)
	return res
}

func TestNotifierDebounce(t *testing.T) {
	in := make(chan model.BlockDecision, 10)
	cfg := model.NotifierConfig{
		DebounceWindow: "50ms",
	}

	n := New(cfg, in)
	mockDest := &mockDestination{}
	n.destinations = []Destination{mockDest}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go n.Run(ctx)

	// Send decisions
	in <- model.BlockDecision{
		IP:     net.ParseIP("198.51.100.1"),
		Reason: model.ReasonRateLimit,
		Detail: "DDoS mitigation test 1",
	}
	in <- model.BlockDecision{
		IP:     net.ParseIP("198.51.100.2"),
		Reason: model.ReasonPortScan,
		Detail: "DDoS mitigation test 2",
	}

	// Wait for debounce window flush
	deadline := time.Now().Add(1 * time.Second)
	for mockDest.Calls() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	calls := mockDest.Calls()
	if calls == 0 {
		t.Fatal("expected notifier to flush pending alerts, got 0 calls to destination")
	}

	decisions := mockDest.Decisions()
	if len(decisions) != 2 {
		t.Errorf("expected 2 decisions flushed, got: %d", len(decisions))
	}

	if decisions[0].IP.String() != "198.51.100.1" {
		t.Errorf("expected first flushed IP to be 198.51.100.1, got %s", decisions[0].IP.String())
	}
}

func TestDestinationNames(t *testing.T) {
	slack := &slackDestination{webhookURL: "http://example.com", client: nil}
	if slack.Name() != "slack" {
		t.Errorf("expected slackDestination.Name() == 'slack', got %q", slack.Name())
	}

	discord := &discordDestination{webhookURL: "http://example.com", client: nil}
	if discord.Name() != "discord" {
		t.Errorf("expected discordDestination.Name() == 'discord', got %q", discord.Name())
	}
}

func TestSlackDestinationSend(t *testing.T) {
	// Spin up a mock HTTP server to intercept the Slack webhook payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json Content-Type, got %s", r.Header.Get("Content-Type"))
		}

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode JSON payload: %v", err)
		}

		// Verify text field
		text, ok := payload["text"].(string)
		if !ok || text != "🛡️ NetShield blocked 1 IP(s)" {
			t.Errorf("expected summary text in payload, got %v", payload["text"])
		}

		// Verify blocks
		blocks, ok := payload["blocks"].([]any)
		if !ok || len(blocks) != 6 { // header, summary, divider, detail, divider, context
			t.Errorf("expected 6 blocks in array, got %d: %v", len(blocks), payload["blocks"])
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := httputils.NewClient()
	slackDest := &slackDestination{
		webhookURL: server.URL,
		client:     client,
	}

	decisions := []model.BlockDecision{
		{
			IP:     net.ParseIP("192.0.2.1"),
			Reason: model.ReasonRateLimit,
			Detail: "rate limit exceeded",
		},
	}

	err := slackDest.Send(context.Background(), decisions)
	if err != nil {
		t.Fatalf("unexpected error sending slack alert: %v", err)
	}
}
