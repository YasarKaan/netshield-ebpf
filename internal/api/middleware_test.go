package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/YasarKaan/netshield-ebpf/internal/blocker"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

func TestAuthMiddleware(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()
	hub := NewWSHub()

	secretToken := "secret-test-token"
	cfg := model.APIConfig{
		ListenAddr: ":8080",
		Auth: model.AuthConfig{
			Enabled: true,
			Token:   secretToken,
		},
	}

	server := NewServer(cfg, "", blk, hub, true, "lo0")

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := server.auth(nextHandler)

	// 1. Missing authorization header
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rr := httptest.NewRecorder()
	authHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", rr.Code)
	}

	// 2. Correct bearer token
	req = httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("Authorization", "Bearer "+secretToken)
	rr = httptest.NewRecorder()
	authHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for correct Bearer token, got %d", rr.Code)
	}

	// 3. Bypass health endpoint
	req = httptest.NewRequest("GET", "/api/v1/health", nil)
	rr = httptest.NewRecorder()
	authHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for unauthenticated health endpoint bypass, got %d", rr.Code)
	}

	// 4. WebSocket query token allowed
	req = httptest.NewRequest("GET", "/ws?token="+secretToken, nil)
	req.Header.Set("Upgrade", "websocket")
	rr = httptest.NewRecorder()
	authHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for WS upgrade query string token, got %d", rr.Code)
	}

	// 5. REST endpoint query token rejected (REST API hardening check)
	req = httptest.NewRequest("GET", "/api/v1/stats?token="+secretToken, nil)
	rr = httptest.NewRecorder()
	authHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for REST API query token, got %d", rr.Code)
	}
}

func TestCORSMiddleware(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()
	server := NewServer(model.APIConfig{}, "", blk, nil, true, "lo0")

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := server.cors(nextHandler)

	req := httptest.NewRequest("OPTIONS", "/api/v1/stats", nil)
	rr := httptest.NewRecorder()
	corsHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 No Content for OPTIONS preflight, got %d", rr.Code)
	}

	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected CORS headers to allow all origins")
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()
	server := NewServer(model.APIConfig{}, "", blk, nil, true, "lo0")

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated panic")
	})

	recoveryHandler := server.recovery(panicHandler)

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rr := httptest.NewRecorder()
	recoveryHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error on panic recovery, got %d", rr.Code)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()
	server := NewServer(model.APIConfig{}, "", blk, nil, true, "lo0")

	// nextHandler writes a non-default status to exercise WriteHeader path
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	loggingHandler := server.logging(nextHandler)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	loggingHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("expected logging middleware to pass through 202 status, got %d", rr.Code)
	}
}

func TestResponseWriterDefaults(t *testing.T) {
	blk := blocker.New(context.Background(), nil, nil, true)
	defer blk.Close()
	server := NewServer(model.APIConfig{}, "", blk, nil, true, "lo0")

	// When the next handler does NOT call WriteHeader the status stays 200.
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok")) //nolint:errcheck
	})

	loggingHandler := server.logging(nextHandler)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	loggingHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected default 200 when handler doesn't call WriteHeader, got %d", rr.Code)
	}
}
