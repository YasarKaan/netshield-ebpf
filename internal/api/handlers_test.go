package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/YasarKaan/netshield-ebpf/internal/blocker"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

func TestAPIHandlers(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()
	hub := NewWSHub()

	cfg := model.APIConfig{
		ListenAddr: ":8080",
		Auth: model.AuthConfig{
			Enabled: false,
		},
	}

	server := NewServer(cfg, "", blk, hub, true, "lo0")

	// 1. Test GET /api/v1/health
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	server.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected health status 200, got %d", rr.Code)
	}

	// 2. Test POST /api/v1/blocklist
	addReq := AddBlockRequest{
		IP:      "198.51.100.44",
		Comment: "Manual block test",
	}
	body, _ := json.Marshal(addReq)
	req = httptest.NewRequest("POST", "/api/v1/blocklist", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	server.handleAddBlocklist(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected POST status 201, got %d", rr.Code)
	}

	// 3. Test GET /api/v1/blocklist
	req = httptest.NewRequest("GET", "/api/v1/blocklist", nil)
	rr = httptest.NewRecorder()
	server.handleListBlocklist(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected GET status 200, got %d", rr.Code)
	}

	var listData map[string]any
	json.Unmarshal(rr.Body.Bytes(), &listData)
	if int(listData["total"].(float64)) != 1 {
		t.Errorf("expected 1 blocked entry, got %v", listData["total"])
	}
	entries := listData["entries"].([]any)
	entry := entries[0].(map[string]any)
	if entry["country"] == "" {
		t.Errorf("expected blocklist entry to include country enrichment")
	}

	// 4. Test GET /api/v1/stats
	req = httptest.NewRequest("GET", "/api/v1/stats", nil)
	rr = httptest.NewRecorder()
	server.handleStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected stats status 200, got %d", rr.Code)
	}

	// 5. Test GET /api/v1/events
	req = httptest.NewRequest("GET", "/api/v1/events?limit=5&since=2026-05-26T00:00:00Z", nil)
	rr = httptest.NewRecorder()
	server.handleEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected events status 200, got %d", rr.Code)
	}
	var eventsResp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &eventsResp)
	events := eventsResp["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0].(map[string]any)
	if event["country"] == "" {
		t.Errorf("expected event to include country enrichment")
	}

	// 6. Test GET /api/v1/events with invalid since format (400 Bad Request)
	req = httptest.NewRequest("GET", "/api/v1/events?since=invalid-format", nil)
	rr = httptest.NewRecorder()
	server.handleEvents(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected events invalid format status 400, got %d", rr.Code)
	}

	// 7. Test DELETE /api/v1/blocklist/{ip}
	// Note: Path routing is mapped by ServeMux in Start(), so we simulate directly
	req = httptest.NewRequest("DELETE", "/api/v1/blocklist/198.51.100.44", nil)
	req.SetPathValue("ip", "198.51.100.44")
	rr = httptest.NewRecorder()
	server.handleRemoveBlocklist(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected DELETE status 204, got %d", rr.Code)
	}

	if blk.GetBlockedIPCount() != 0 {
		t.Errorf("expected blocker to be empty after remove")
	}
}

func TestHandleAddBlocklistAcceptsIPv6(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()

	server := NewServer(model.APIConfig{}, "", blk, NewWSHub(), true, "lo0")

	// Global unicast IPv6 address — must be accepted now that we support dual-stack.
	body, _ := json.Marshal(AddBlockRequest{
		IP:      "2001:db8::cafe",
		Comment: "ipv6 block test",
	})
	req := httptest.NewRequest("POST", "/api/v1/blocklist", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	server.handleAddBlocklist(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for valid IPv6 block request, got %d (body: %s)", rr.Code, rr.Body.String())
	}

	// Verify it appears in the blocklist.
	req = httptest.NewRequest("GET", "/api/v1/blocklist", nil)
	rr = httptest.NewRecorder()
	server.handleListBlocklist(rr, req)

	var listData map[string]any
	json.Unmarshal(rr.Body.Bytes(), &listData)
	if int(listData["total"].(float64)) != 1 {
		t.Errorf("expected 1 blocked entry after IPv6 block, got %v", listData["total"])
	}
}

func TestHandleAddBlocklistRejectsInvalidIP(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()

	server := NewServer(model.APIConfig{}, "", blk, NewWSHub(), true, "lo0")

	body, _ := json.Marshal(AddBlockRequest{
		IP:      "not-an-ip",
		Comment: "invalid ip should be rejected",
	})
	req := httptest.NewRequest("POST", "/api/v1/blocklist", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	server.handleAddBlocklist(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid IP, got %d", rr.Code)
	}
}

func TestHandleAddBlocklistRejectsDuplicate(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()

	server := NewServer(model.APIConfig{}, "", blk, NewWSHub(), true, "lo0")
	body, _ := json.Marshal(AddBlockRequest{
		IP:      "198.51.100.60",
		Comment: "first",
	})

	req := httptest.NewRequest("POST", "/api/v1/blocklist", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	server.handleAddBlocklist(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected first request to succeed, got %d", rr.Code)
	}

	req = httptest.NewRequest("POST", "/api/v1/blocklist", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	server.handleAddBlocklist(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected duplicate request to return 409, got %d", rr.Code)
	}
}

func TestHandleRemoveBlocklistMissingReturns404(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()

	server := NewServer(model.APIConfig{}, "", blk, NewWSHub(), true, "lo0")
	req := httptest.NewRequest("DELETE", "/api/v1/blocklist/198.51.100.61", nil)
	req.SetPathValue("ip", "198.51.100.61")
	rr := httptest.NewRecorder()

	server.handleRemoveBlocklist(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing IP, got %d", rr.Code)
	}
}

func (s *Server) AddEventForTesting(ev model.BlockEntry) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	s.events = append(s.events, ev)
}

func TestAPIEventsFiltering(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()
	hub := NewWSHub()
	cfg := model.APIConfig{ListenAddr: ":8080"}
	server := NewServer(cfg, "", blk, hub, true, "lo0")

	// Inject events
	now := time.Now()
	server.AddEventForTesting(model.BlockEntry{
		IP:        net.ParseIP("192.0.2.1"),
		Reason:    "rate_limit",
		BlockedAt: now.Add(-10 * time.Minute),
		Detail:    "Rate test",
	})
	server.AddEventForTesting(model.BlockEntry{
		IP:        net.ParseIP("192.0.2.2"),
		Reason:    "port_scan",
		BlockedAt: now.Add(-1 * time.Minute),
		Detail:    "Scan test",
	})

	// Filter since 5 minutes ago
	sinceTime := now.Add(-5 * time.Minute).Format(time.RFC3339)
	req := httptest.NewRequest("GET", "/api/v1/events?since="+url.QueryEscape(sinceTime), nil)
	rr := httptest.NewRecorder()
	server.handleEvents(rr, req)

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)
	eventsSlice := resp["events"].([]any)

	if len(eventsSlice) != 1 {
		t.Errorf("expected 1 filtered event since 5 minutes ago, got %d", len(eventsSlice))
	}
}
