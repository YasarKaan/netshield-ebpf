package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/YasarKaan/go-kit/loggerutils"
	"github.com/YasarKaan/netshield-ebpf/internal/blocker"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type AddBlockRequest struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func (s *Server) handleListBlocklist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.blocker.List()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range entries {
		if entries[i].Country != "" || entries[i].Lat != 0 || entries[i].Lon != 0 {
			continue
		}
		if s.geoIPClient != nil {
			entries[i].Country, entries[i].Lat, entries[i].Lon = s.geoIPClient.Lookup(entries[i].IP)
			continue
		}
		entries[i].Country, entries[i].Lat, entries[i].Lon = "US", 37.751, -97.822
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   len(entries),
	})
}

func (s *Server) handleAddBlocklist(w http.ResponseWriter, r *http.Request) {
	var req AddBlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ip := net.ParseIP(req.IP)
	if ip == nil {
		s.writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	err := s.blocker.Block(r.Context(), ip, model.ReasonManual, 0, req.Comment)
	if err != nil {
		if errors.Is(err, blocker.ErrAlreadyBlocked) {
			s.writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now()
	s.AddEvent(model.BlockEntry{
		IP:        ip,
		Reason:    model.ReasonManual.String(),
		BlockedAt: now,
		Detail:    req.Comment,
	})

	s.hub.Broadcast(s.FormatWSBlockEvent(ip.String(), model.ReasonManual.String(), req.Comment, now))

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"ip":         ip.String(),
		"reason":     "manual",
		"blocked_at": now,
	})
}

func (s *Server) handleRemoveBlocklist(w http.ResponseWriter, r *http.Request) {
	ipStr := r.PathValue("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		s.writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	err := s.blocker.Unblock(r.Context(), ip)
	if err != nil {
		if errors.Is(err, blocker.ErrNotBlocked) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	activeBlocks := s.blocker.GetBlockedIPCount()

	s.writeJSON(w, http.StatusOK, map[string]any{
		"total_packets":   s.stats.TotalPackets,
		"dropped_packets": s.stats.DroppedPackets,
		"passed_packets":  s.stats.PassedPackets,
		"active_blocks":   activeBlocks,
		"pps_current":     s.stats.PPSCurrent,
		"uptime_seconds":  int(time.Since(s.startTime).Seconds()),
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.eventsMu.RLock()
	defer s.eventsMu.RUnlock()

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	reason := r.URL.Query().Get("reason")
	sinceStr := r.URL.Query().Get("since")

	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	var sinceTime time.Time
	if sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			sec, err2 := strconv.ParseInt(sinceStr, 10, 64)
			if err2 != nil {
				s.writeError(w, http.StatusBadRequest, "invalid since parameter format: must be RFC3339 or Unix timestamp")
				loggerutils.Warn("Invalid since parameter format: {}", map[string]any{"since": sinceStr})
				return
			}
			sinceTime = time.Unix(sec, 0)
		} else {
			sinceTime = t
		}
	}

	var filtered []model.BlockEntry
	for i := len(s.events) - 1; i >= 0; i-- { // Newest first
		ev := s.events[i]
		if reason != "" && ev.Reason != reason {
			continue
		}
		if !sinceTime.IsZero() && ev.BlockedAt.Before(sinceTime) {
			continue
		}
		filtered = append(filtered, ev)
	}

	total := len(filtered)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	paginated := filtered[start:end]

	s.writeJSON(w, http.StatusOK, map[string]any{
		"events": paginated,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"xdp_attached": !s.mockMode,
		"interface":    s.interfaceName,
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		loggerutils.Error("failed to encode json response", map[string]any{
			"status": status,
			"err":    err.Error(),
		})
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(append(payload, '\n')); err != nil {
		loggerutils.Warn("failed to write json response", map[string]any{
			"status": status,
			"err":    err.Error(),
		})
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}
