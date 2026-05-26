package api

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/YasarKaan/go-kit/loggerutils"
	"github.com/YasarKaan/netshield-ebpf/internal/exporter"
)

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/v1/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			if r.Header.Get("Upgrade") == "websocket" || r.URL.Path == "/ws" {
				token = r.URL.Query().Get("token")
			}
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Auth.Token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		statusStr := fmt.Sprintf("%d", rw.statusCode)
		exporter.APIRequestDuration.WithLabelValues(r.Method, r.URL.Path, statusStr).Observe(duration.Seconds())

		loggerutils.Info("API request processed", map[string]any{
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   rw.statusCode,
			"duration": duration.String(),
			"remote":   r.RemoteAddr,
		})
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				loggerutils.Error("API handler panicked", map[string]any{
					"err":  err,
					"path": r.URL.Path,
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal server error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
