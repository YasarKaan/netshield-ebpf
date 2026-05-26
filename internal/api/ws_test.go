package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketHub(t *testing.T) {
	hub := NewWSHub()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.ServeHTTP(w, r)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	u.Scheme = "ws"

	// Connect first client
	conn1, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("failed to dial first websocket: %v", err)
	}
	defer conn1.Close()

	// Connect second client
	conn2, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("failed to dial second websocket: %v", err)
	}
	defer conn2.Close()

	// Broadcast test payload
	testPayload := []byte("alert: test block event")
	hub.Broadcast(testPayload)

	// Read from first client
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, p1, err := conn1.ReadMessage()
	if err != nil {
		t.Fatalf("first client failed to read message: %v", err)
	}
	if msgType != websocket.TextMessage {
		t.Errorf("expected text message, got %d", msgType)
	}
	if string(p1) != "alert: test block event" {
		t.Errorf("expected payload 'alert: test block event', got %q", string(p1))
	}

	// Read from second client
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, p2, err := conn2.ReadMessage()
	if err != nil {
		t.Fatalf("second client failed to read message: %v", err)
	}
	if string(p2) != "alert: test block event" {
		t.Errorf("expected payload 'alert: test block event', got %q", string(p2))
	}
}
