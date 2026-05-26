package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/YasarKaan/go-kit/loggerutils"
	"github.com/YasarKaan/netshield-ebpf/internal/blocker"
	"github.com/YasarKaan/netshield-ebpf/pkg/geoip"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type APIStats struct {
	TotalPackets   uint64
	DroppedPackets uint64
	PassedPackets  uint64
	PPSCurrent     uint64
}

type Server struct {
	blocker       *blocker.Blocker
	hub           *WSHub
	cfg           model.APIConfig
	eventsMu      sync.RWMutex
	events        []model.BlockEntry
	statsMu       sync.RWMutex
	stats         APIStats
	startTime     time.Time
	mockMode      bool
	interfaceName string
	geoIPClient   *geoip.LookupClient
}

func NewServer(cfg model.APIConfig, geoIPPath string, blk *blocker.Blocker, hub *WSHub, mockMode bool, interfaceName string) *Server {
	geoClient, err := geoip.New(geoIPPath)
	if err != nil {
		loggerutils.Error("Failed to initialize GeoIP reader: {}", map[string]any{"err": err.Error()})
	}

	if geoClient == nil || geoClient.IsMock() {
		if geoIPPath == "" {
			loggerutils.Warn("GeoIP database path not configured. Falling back to mock local subnet coordinate mappings.")
		} else {
			loggerutils.Warn("GeoIP database file not found at: {}. Falling back to mock local subnet coordinate mappings.", geoIPPath)
		}
	} else {
		loggerutils.Info("GeoIP database loaded successfully from: {}", geoIPPath)
	}

	return &Server{
		blocker:       blk,
		hub:           hub,
		cfg:           cfg,
		events:        make([]model.BlockEntry, 0),
		startTime:     time.Now(),
		mockMode:      mockMode,
		interfaceName: interfaceName,
		geoIPClient:   geoClient,
	}
}


func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/blocklist", s.handleListBlocklist)
	mux.HandleFunc("POST /api/v1/blocklist", s.handleAddBlocklist)
	mux.HandleFunc("DELETE /api/v1/blocklist/{ip}", s.handleRemoveBlocklist)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /ws", s.hub.ServeHTTP)
	mux.Handle("GET /metrics", promhttp.Handler())

	handler := s.recovery(s.cors(s.logging(s.auth(mux))))

	srv := &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		loggerutils.Info("Shutting down API server...")
		if s.geoIPClient != nil {
			_ = s.geoIPClient.Close()
		}
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	go s.startStatsBroadcast(ctx)

	loggerutils.Info("API server listening on {}", map[string]any{"addr": s.cfg.ListenAddr})
	return srv.ListenAndServe()
}

func (s *Server) AddEvent(ev model.BlockEntry) {
	if ev.Country == "" && ev.Lat == 0 && ev.Lon == 0 {
		if s.geoIPClient != nil {
			ev.Country, ev.Lat, ev.Lon = s.geoIPClient.Lookup(ev.IP)
		} else {
			ev.Country, ev.Lat, ev.Lon = "US", 37.751, -97.822
		}
	}
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	if len(s.events) >= 1000 {
		s.events = s.events[1:]
	}
	s.events = append(s.events, ev)
}


func (s *Server) UpdateStats(stats APIStats) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.stats = stats
}

func (s *Server) FormatWSBlockEvent(ip, reason, detail string, t time.Time) []byte {
	var country string
	var lat, lon float64
	if s.geoIPClient != nil {
		country, lat, lon = s.geoIPClient.Lookup(net.ParseIP(ip))
	} else {
		country, lat, lon = "US", 37.751, -97.822
	}
	msg := model.WSMessage{
		Type:      "block_event",
		Timestamp: t,
		IP:        ip,
		Reason:    reason,
		Detail:    detail,
		Country:   country,
		Lat:       lat,
		Lon:       lon,
	}
	b, _ := json.Marshal(msg)
	return b
}

func (s *Server) startStatsBroadcast(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.statsMu.RLock()
			activeBlocks := s.blocker.GetBlockedIPCount()
			msg := model.WSMessage{
				Type:           "stats_update",
				Timestamp:      time.Now(),
				TotalPackets:   s.stats.TotalPackets,
				DroppedPackets: s.stats.DroppedPackets,
				ActiveBlocks:   uint32(activeBlocks),
				PPSCurrent:     s.stats.PPSCurrent,
			}
			s.statsMu.RUnlock()

			b, _ := json.Marshal(msg)
			s.hub.Broadcast(b)
		}
	}
}

