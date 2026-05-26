package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/YasarKaan/netshield-ebpf/internal/blocker"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

func newTestServer(t *testing.T) (*Server, *blocker.Blocker) {
	t.Helper()
	blk := blocker.New(context.Background(), nil, nil, true)
	hub := NewWSHub()
	srv := NewServer(model.APIConfig{}, "", blk, hub, true, "lo0")
	return srv, blk
}

func TestUpdateStats(t *testing.T) {
	srv, blk := newTestServer(t)
	defer blk.Close()

	srv.UpdateStats(APIStats{
		TotalPackets:   1000,
		DroppedPackets: 50,
		PassedPackets:  950,
		PPSCurrent:     120,
	})

	srv.statsMu.RLock()
	got := srv.stats
	srv.statsMu.RUnlock()

	if got.TotalPackets != 1000 {
		t.Errorf("TotalPackets: got %d, want 1000", got.TotalPackets)
	}
	if got.DroppedPackets != 50 {
		t.Errorf("DroppedPackets: got %d, want 50", got.DroppedPackets)
	}
	if got.PPSCurrent != 120 {
		t.Errorf("PPSCurrent: got %d, want 120", got.PPSCurrent)
	}
}

func TestFormatWSBlockEvent(t *testing.T) {
	srv, blk := newTestServer(t)
	defer blk.Close()

	msg := srv.FormatWSBlockEvent("1.2.3.4", "rate_limit", "exceeded threshold", time.Now())
	if len(msg) == 0 {
		t.Fatal("FormatWSBlockEvent returned empty bytes")
	}

	var parsed map[string]any
	if err := json.Unmarshal(msg, &parsed); err != nil {
		t.Fatalf("FormatWSBlockEvent returned invalid JSON: %v", err)
	}
	if parsed["type"] != "block_event" {
		t.Errorf("expected type=block_event, got %v", parsed["type"])
	}
	if parsed["ip"] != "1.2.3.4" {
		t.Errorf("expected ip=1.2.3.4, got %v", parsed["ip"])
	}
	if parsed["reason"] != "rate_limit" {
		t.Errorf("expected reason=rate_limit, got %v", parsed["reason"])
	}
	if parsed["country"] == "" {
		t.Errorf("expected country to be populated via GeoIP fallback")
	}
}

func TestStartStatsBroadcast(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()

	hub := NewWSHub()
	srv := NewServer(model.APIConfig{}, "", blk, hub, true, "lo0")
	srv.UpdateStats(APIStats{TotalPackets: 42, DroppedPackets: 7, PPSCurrent: 5})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)

	// Serve WebSocket from a test HTTP server backed by the hub.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.ServeHTTP(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	u.Scheme = "ws"

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("failed to connect websocket client: %v", err)
	}
	defer conn.Close()

	// Allow the hub to register the client before the first tick fires.
	time.Sleep(50 * time.Millisecond)

	// startStatsBroadcast ticks every 2 s; give it up to 3 s.
	broadcastCtx, broadcastCancel := context.WithTimeout(ctx, 3*time.Second)
	defer broadcastCancel()
	go srv.startStatsBroadcast(broadcastCtx)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("did not receive stats broadcast within timeout: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(msgBytes, &parsed); err != nil {
		t.Fatalf("stats broadcast is not valid JSON: %v", err)
	}
	if parsed["type"] != "stats_update" {
		t.Errorf("expected type=stats_update, got %v", parsed["type"])
	}
	if parsed["total_packets"] == nil {
		t.Errorf("expected total_packets field in stats broadcast")
	}
}
