package notifier

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/YasarKaan/go-kit/httputils"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

func TestDiscordDestinationSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json Content-Type, got %s", r.Header.Get("Content-Type"))
		}

		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode JSON payload: %v", err)
		}

		content := payload["content"]
		if content == "" {
			t.Fatal("expected discord payload content to be populated")
		}
		if want := "192.0.2.9"; !strings.Contains(content, want) {
			t.Fatalf("expected discord payload to include IP %s, got %q", want, content)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dest := &discordDestination{
		webhookURL: server.URL,
		client:     httputils.NewClient(),
	}

	err := dest.Send(context.Background(), []model.BlockDecision{
		{
			IP:     net.ParseIP("192.0.2.9"),
			Reason: model.ReasonPortScan,
			Detail: "scan detected",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error sending discord alert: %v", err)
	}
}
