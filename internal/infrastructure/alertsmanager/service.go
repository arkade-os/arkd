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
	baseUrl    string
	esploraUrl string
	httpClient *http.Client
}

func NewService(alertManagerURL, esploraURL string) ports.Alerts {
	return &service{
		baseUrl:    alertManagerURL,
		esploraUrl: esploraURL,
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
		annotations["firing_title"] = "🎯 Batch Finalized"
		m, ok := message.(ports.BatchFinalizedAlert)
		if !ok {
			return fmt.Errorf("invalid message type: %T", message)
		}
		desc = formatBatchFinalizedAlert(s.esploraUrl, m)
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
		req, err := http.NewRequestWithContext(ctx, "POST", s.baseUrl, bytes.NewReader(payload))
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

func formatBatchFinalizedAlert(esploraUrl string, data ports.BatchFinalizedAlert) string {
	lines := make([]string, 0)
	lines = append(lines, fmt.Sprintf("%s/tx/%s", esploraUrl, data.CommitmentTxid))
	lines = append(lines, fmt.Sprintf("\n*ID:* `%s`", data.Id))

	totBalance := data.LiquidityProviderConfirmedBalance + data.LiquidityProviderUnconfirmedBalance
	lines = append(lines, "\n*Liquidity Metrics:*")
	lines = append(lines, fmt.Sprintf(
		"• Liquidity provided: %s", formatBTC(data.LiquidityProvided),
	))
	lines = append(lines, fmt.Sprintf(
		"• Liquidity Provider Balance: %s (%s)", formatBTC(totBalance), data.LiquidityCost,
	))

	lines = append(lines, "\n*Details:*")
	if data.ExitAmount > 0 {
		l := "utxo"
		if data.ExitCount > 1 {
			l = "utxos"
		}
		lines = append(lines, fmt.Sprintf(
			"• Exit amount (%d %s): %s", data.ExitCount, l, formatBTC(data.ExitAmount),
		))
	}
	if data.BoardingInputAmount > 0 {
		l := "utxo"
		if data.BoardingInputCount > 1 {
			l = "utxos"
		}
		lines = append(lines, fmt.Sprintf(
			"• Boarding amount (%d %s): %s",
			data.BoardingInputCount, l, formatBTC(data.BoardingInputAmount),
		))
	}
	if data.LeafAmount > 0 {
		l := "leaf"
		if data.LeafCount > 1 {
			l = "leaves"
		}
		lines = append(lines, fmt.Sprintf(
			"• Batch amount (%d %s): %s", data.LeafCount, l, formatBTC(data.LeafAmount),
		))
	}
	if data.ForfeitAmount > 0 {
		l := "vtxo"
		if data.ForfeitCount > 1 {
			l = "vtxos"
		}
		lines = append(lines, fmt.Sprintf(
			"• Forfeit amount (%d %s): %s", data.ForfeitCount, l, formatBTC(data.ForfeitAmount),
		))
	}
	lines = append(lines, fmt.Sprintf("• Intents: %d", data.IntentsCount))
	lines = append(lines, fmt.Sprintf("• Duration: %s", data.Duration))

	lines = append(lines, "\n*Liquidity Provider Balance:*")
	lines = append(lines, fmt.Sprintf(
		"• Confirmed: %s", formatBTC(data.LiquidityProviderConfirmedBalance),
	))
	lines = append(lines, fmt.Sprintf(
		"• Unconfirmed: %s", formatBTC(data.LiquidityProviderUnconfirmedBalance),
	))

	lines = append(lines, "\n*Fees:*")
	lines = append(lines, fmt.Sprintf("• Network fees: -%d sats", data.OnchainFees))
	sign := ""
	if data.CollectedFees > 0 {
		sign = "+"
	}
	lines = append(lines, fmt.Sprintf("• Collected fees: %s%d sats", sign, data.CollectedFees))
	return strings.Join(lines, "\n")
}

func formatGenericAlert(data map[string]any) string {
	lines := make([]string, 0)
	for key, value := range data {
		lines = append(lines, fmt.Sprintf("• %s: %v", key, value))
	}
	return strings.Join(lines, "\n")
}

func formatBTC(sats uint64) string {
	const satsPerBTC = 100_000_000

	whole := sats / satsPerBTC
	frac := sats % satsPerBTC

	if frac == 0 {
		return fmt.Sprintf("%d BTC", whole)
	}

	// Format fractional part as 8-digit zero-padded
	f := fmt.Sprintf("%08d", frac)

	// Trim trailing zeros
	f = strings.TrimRight(f, "0")

	return fmt.Sprintf("%d.%s BTC", whole, f)
}
