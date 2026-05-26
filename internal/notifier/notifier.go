package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/YasarKaan/go-kit/enums"
	"github.com/YasarKaan/go-kit/httputils"
	"github.com/YasarKaan/go-kit/loggerutils"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type Destination interface {
	Send(ctx context.Context, decisions []model.BlockDecision) error
	Name() string
}

type Notifier struct {
	destinations []Destination
	in           <-chan model.BlockDecision
	cfg          model.NotifierConfig
	client       *httputils.Client
}

func New(cfg model.NotifierConfig, in <-chan model.BlockDecision) *Notifier {
	client := httputils.NewClient(
		httputils.WithTimeout(5*time.Second),
		httputils.WithMaxRetries(3),
	)

	var destinations []Destination
	if cfg.Slack.Enabled && cfg.Slack.WebhookURL != "" {
		destinations = append(destinations, &slackDestination{webhookURL: cfg.Slack.WebhookURL, client: client})
	}
	if cfg.Discord.Enabled && cfg.Discord.WebhookURL != "" {
		destinations = append(destinations, &discordDestination{webhookURL: cfg.Discord.WebhookURL, client: client})
	}

	return &Notifier{
		destinations: destinations,
		in:           in,
		cfg:          cfg,
		client:       client,
	}
}

func (n *Notifier) Run(ctx context.Context) {
	window, err := time.ParseDuration(n.cfg.DebounceWindow)
	if err != nil {
		window = 10 * time.Second
	}

	loggerutils.InfoContext(ctx, "Starting notifier worker with debounce window: {}...", window)

	ticker := time.NewTicker(window)
	defer ticker.Stop()

	var pending []model.BlockDecision

	for {
		select {
		case <-ctx.Done():
			if len(pending) > 0 {
				flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				n.flush(flushCtx, pending)
				cancel()
			}
			return
		case d, ok := <-n.in:
			if !ok {
				if len(pending) > 0 {
					n.flush(ctx, pending)
				}
				return
			}
			pending = append(pending, d)
		case <-ticker.C:
			if len(pending) == 0 {
				continue
			}
			n.flush(ctx, pending)
			pending = nil
		}
	}
}

func (n *Notifier) flush(ctx context.Context, decisions []model.BlockDecision) {
	loggerutils.InfoContext(ctx, "Dispatching batch of {} block alerts to channels", len(decisions))
	var wg sync.WaitGroup
	for _, dest := range n.destinations {
		wg.Add(1)
		go func(d Destination) {
			defer wg.Done()
			err := d.Send(ctx, decisions)
			if err != nil {
				loggerutils.ErrorContext(ctx, "failed to send notification to {}", map[string]any{
					"destination": d.Name(),
					"err":         err.Error(),
				})
			}
		}(dest)
	}
	wg.Wait()
}

type slackDestination struct {
	webhookURL string
	client     *httputils.Client
}

func (s *slackDestination) Name() string { return "slack" }

func (s *slackDestination) Send(ctx context.Context, decisions []model.BlockDecision) error {
	if len(decisions) == 0 {
		return nil
	}

	summaryText := fmt.Sprintf("🛡️ NetShield blocked %d IP(s)", len(decisions))

	var blocks []any

	// Header block
	blocks = append(blocks, map[string]any{
		"type": "header",
		"text": map[string]any{
			"type":  "plain_text",
			"text":  "🛡️ NetShield Security Alert",
			"emoji": true,
		},
	})

	// Summary section block
	blocks = append(blocks, map[string]any{
		"type": "section",
		"text": map[string]any{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*NetShield has blocked %d IP address(es) due to detected threats:*", len(decisions)),
		},
	})

	// Divider
	blocks = append(blocks, map[string]any{
		"type": "divider",
	})

	// Detail sections
	for _, d := range decisions {
		threatClass := d.Reason.ThreatClassification()
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("• *IP:* `%s`\n  *Threat:* `%s` (%s)\n  *Detail:* %s",
					d.IP.String(), threatClass, d.Reason.String(), d.Detail),
			},
		})
	}

	// Divider before context
	blocks = append(blocks, map[string]any{
		"type": "divider",
	})

	// Context block
	nowStr := time.Now().Format(time.RFC3339)
	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []any{
			map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("📅 *Time:* `%s`  •  🤖 *Agent:* NetShield eBPF", nowStr),
			},
		},
	})

	payloadMap := map[string]any{
		"text":   summaryText,
		"blocks": blocks,
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	_, err = s.client.SendRequest(ctx, s.webhookURL, enums.MethodPost, nil, payloadBytes, enums.ContentTypeJSON)
	return err
}

type discordDestination struct {
	webhookURL string
	client     *httputils.Client
}

func (d *discordDestination) Name() string { return "discord" }

func (d *discordDestination) Send(ctx context.Context, decisions []model.BlockDecision) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🛡️ **NetShield blocked %d IP(s)**\n\n", len(decisions)))
	for _, dec := range decisions {
		sb.WriteString(fmt.Sprintf("• **%s**  •  %s  •  %s\n", dec.IP.String(), dec.Reason.String(), dec.Detail))
	}

	payloadMap := map[string]string{
		"content": sb.String(),
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	_, err = d.client.SendRequest(ctx, d.webhookURL, enums.MethodPost, nil, payloadBytes, enums.ContentTypeJSON)
	return err
}
