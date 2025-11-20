package alertsmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/shopspring/decimal"
)

const (
	serviceName = "arkd"
	severity    = "info"

	maxRetries = 5
)

type Alert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
}

type service struct {
	baseURL    string
	httpClient *http.Client
}

func NewService(alertManagerURL string) ports.Alerts {
	return &service{
		baseURL: alertManagerURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *service) Publish(ctx context.Context, topic ports.Topic, message any) error {
	labels := map[string]string{
		"alertname": string(topic),
		"service":   serviceName,
		"severity":  severity,
	}

	desc := ""
	annotations := map[string]string{}
	switch topic {
	case ports.BatchFinalized:
		annotations["firing_title"] = "🗳 Batch Finalized"
		m, ok := message.(ports.BatchFinalizedAlert)
		if !ok {
			return fmt.Errorf("invalid message type: %T", message)
		}
		desc = formatBatchFinalizedAlert(m)
		labels["batch_id"] = m.Id
		labels["txid"] = m.CommitmentTxid
	default:
		annotations["firing_title"] = fmt.Sprintf("🔔 %s", topic)
		desc = formatGenericAlert(map[string]any{"event": message})
	}

	annotations["description"] = desc
	alert := Alert{
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    time.Now(),
	}

	if err := s.sendAlert(ctx, alert); err != nil {
		return fmt.Errorf("failed to send alert to AlertManager: %w", err)
	}

	return nil
}

func (s *service) sendAlert(ctx context.Context, alerts Alert) error {
	payload, err := json.Marshal([]Alert{alerts})
	if err != nil {
		return fmt.Errorf("failed to marshal alerts: %w", err)
	}

	baseDelay := 100 * time.Millisecond

	for attempt := range maxRetries {
		req, err := http.NewRequestWithContext(ctx, "POST", s.baseURL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			// Network error - retry with backoff
			if attempt < maxRetries-1 {
				// exponential: 100ms, 200ms, 400ms, 800ms, 1600ms
				delay := baseDelay * time.Duration(1<<uint(attempt))

				select {
				case <-time.After(delay):
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return fmt.Errorf("failed to send alert after %d attempts: %w", maxRetries, err)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			_ = resp.Body.Close()
			return nil
		}

		_ = resp.Body.Close()

		// Retry on 5xx (server errors), but not on 4xx (client errors)
		if resp.StatusCode >= 500 {
			if attempt < maxRetries-1 {
				delay := baseDelay * time.Duration(1<<uint(attempt))

				select {
				case <-time.After(delay):
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		// 4xx error or final 5xx error
		return fmt.Errorf(
			"failed to send alert to AlertManager with status %d after %d attempts",
			resp.StatusCode, attempt+1,
		)
	}

	return fmt.Errorf("failed to send alert after %d attempts", maxRetries)
}

func formatBatchFinalizedAlert(data ports.BatchFinalizedAlert) string {
	lines := make([]string, 0)
	lines = append(lines, fmt.Sprintf("*ID:* `%s`", data.Id))
	lines = append(lines, fmt.Sprintf("*TX ID:* `%s`", data.CommitmentTxid))

	outAmount := data.LeafAmount + data.ExitAmount + data.ConnectorsAmount
	totBalance := data.LiqudityProviderConfirmedBalance + data.LiqudityProviderUnconfirmedBalance
	lines = append(lines, "\n*TLDR:*")
	lines = append(lines, fmt.Sprintf("• Total output amount: %s", formatBTC(outAmount)))
	lines = append(lines, fmt.Sprintf("• Boarding input amount: %s", formatBTC(data.BoardingInputAmount)))
	lines = append(lines, fmt.Sprintf("• Liquidity provided: %s", formatBTC(data.LiquidityProviderInputAmount-outAmount)))
	lines = append(lines, fmt.Sprintf("• LP Balance: %s", formatBTC(totBalance)))
	lines = append(lines, fmt.Sprintf("• Liquidity cost: %s", data.LiquidityCost))

	lines = append(lines, "\n*Liquidity Provider Balance:*")
	lines = append(lines, fmt.Sprintf("• Total: %s", formatBTC(totBalance)))
	lines = append(lines, fmt.Sprintf("• Confirmed: %s", formatBTC(data.LiqudityProviderConfirmedBalance)))
	lines = append(lines, fmt.Sprintf("• Unconfirmed: %s", formatBTC(data.LiqudityProviderUnconfirmedBalance)))

	lines = append(lines, "\n*Fees:*")
	lines = append(lines, fmt.Sprintf("• Network fees (spent): %d sats", data.OnchainFees))
	lines = append(lines, fmt.Sprintf("• Collected fees (earned): %d sats", data.CollectedFees))

	lines = append(lines, "\n*Breakdown:*")
	lines = append(lines, fmt.Sprintf("• Duration: %s", data.Duration))
	lines = append(lines, fmt.Sprintf("• Intents: %d", data.IntentsCount))
	lines = append(lines, fmt.Sprintf("• Boarding UTXOs: %d", data.BoardingInputCount))
	lines = append(lines, fmt.Sprintf("• Spent VTXOs: %d", data.ForfeitCount))
	lines = append(lines, fmt.Sprintf("• New VTXOs: %d", data.LeafCount))
	lines = append(lines, fmt.Sprintf("• Boarding amount: %s", formatBTC(data.BoardingInputAmount)))
	lines = append(lines, fmt.Sprintf("• Batch amount: %s", formatBTC(data.LeafAmount)))
	lines = append(lines, fmt.Sprintf("• Exit amount: %s", formatBTC(data.ExitAmount)))
	lines = append(lines, fmt.Sprintf("• Forfeit amount: %s", formatBTC(data.ForfeitAmount)))
	return strings.Join(lines, "\n")
}

func formatGenericAlert(data map[string]interface{}) string {
	lines := make([]string, 0)
	for key, value := range data {
		lines = append(lines, fmt.Sprintf("• %s: %v", key, value))
	}
	return strings.Join(lines, "\n")
}

func formatBTC(val uint64) string {
	if val == 0 {
		return "0 BTC"
	}
	return fmt.Sprintf("%s BTC", decimal.NewFromInt(int64(val)).StringFixed(8))
}
