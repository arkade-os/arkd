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
	log "github.com/sirupsen/logrus"
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

func (s *service) Publish(ctx context.Context, topic ports.Topic, message interface{}) error {
	messageData, ok := message.(map[string]interface{})
	if !ok {
		log.WithField("topic", topic).Warn(
			"alert message is not a map, converting to generic format",
		)
		messageData = map[string]interface{}{
			"event": message,
		}
	}

	labels := map[string]string{
		"alertname": string(topic),
		"service":   serviceName,
		"severity":  severity,
	}

	annotations := map[string]string{}

	switch topic {
	case ports.BatchFinalized:
		annotations["firing_title"] = "ℹ️ Ark Batch Finalized"
	case ports.ArkTx:
		annotations["firing_title"] = "ℹ️ Ark Tx Finalized"
	default:
		annotations["firing_title"] = string(topic)
	}

	if batchID, ok := messageData["batch_id"].(string); ok {
		labels["batch_id"] = batchID
	}
	if txid, ok := messageData["txid"].(string); ok {
		annotations["txid"] = txid
	}

	var descLines []string
	switch topic {
	case ports.BatchFinalized:
		descLines = formatBatchFinalizedAlert(messageData)
	case ports.ArkTx:
		descLines = formatArkTxAlert(messageData)
	default:
		descLines = formatGenericAlert(messageData)
	}

	annotations["description"] = strings.Join(descLines, "\n")
	alert := Alert{
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    time.Now(),
	}

	if err := s.sendAlert(ctx, alert); err != nil {
		return fmt.Errorf("failed to send alert to AlertManager: %w", err)
	}

	log.WithFields(log.Fields{
		"topic":     topic,
		"alertname": labels["alertname"],
		"batch_id":  labels["batch_id"],
	}).Debug("alert sent to AlertManager")

	return nil
}

func (s *service) sendAlert(ctx context.Context, alerts Alert) error {
	payload, err := json.Marshal([]Alert{alerts})
	if err != nil {
		return fmt.Errorf("failed to marshal alerts: %w", err)
	}

	baseDelay := 100 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
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
					return fmt.Errorf("context cancelled during retry: %w", ctx.Err())
				}
			}

			return fmt.Errorf("failed to send alert after %d attempts: %w", maxRetries, err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			_ = resp.Body.Close()
			if attempt > 0 {
				log.WithField("attempts", attempt+1).Info("alert sent to AlertManager after retry")
			}

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
					return fmt.Errorf("context cancelled during retry: %w", ctx.Err())
				}
			}
		}

		// 4xx error or final 5xx error
		return fmt.Errorf(
			"AlertManager returned non-success status %d after %d attempts",
			resp.StatusCode,
			attempt+1,
		)
	}

	return fmt.Errorf("failed to send alert after %d attempts", maxRetries)
}

func formatBatchFinalizedAlert(data map[string]interface{}) []string {
	var lines []string

	if batchID, ok := data["batch_id"].(string); ok {
		lines = append(lines, fmt.Sprintf("*Batch ID:* `%s`", batchID))
	}
	if txid, ok := data["txid"].(string); ok {
		lines = append(lines, fmt.Sprintf("*TX ID:* `%s`", txid))
	}

	hasFinancial := false
	if operatorInput, ok := getInt(data, "operator_input_amount_sats"); ok && operatorInput > 0 {
		if !hasFinancial {
			lines = append(lines, "\n*Financial Metrics:*")
			hasFinancial = true
		}
		btc := float64(operatorInput) / 1e8
		lines = append(
			lines,
			fmt.Sprintf(
				"• Operator Input: %s sats (%.8f BTC)",
				formatNumber(operatorInput),
				btc,
			),
		)
	}
	if miningFee, ok := getInt(data, "mining_fee_sats"); ok {
		if !hasFinancial {
			lines = append(lines, "\n*Financial Metrics:*")
			hasFinancial = true
		}
		lines = append(lines, fmt.Sprintf("• Mining Fee: %s sats", formatNumber(miningFee)))
	}
	if intentFees, ok := getInt(data, "intent_fees_sats"); ok {
		if !hasFinancial {
			lines = append(lines, "\n*Financial Metrics:*")
		}
		lines = append(
			lines,
			fmt.Sprintf("• Intent Fees Earned: %s sats", formatNumber(intentFees)),
		)
	}

	hasBalances := false
	if confirmed, ok := getInt(data, "operator_comfirmed_balacnce"); ok {
		if !hasBalances {
			lines = append(lines, "\n*Operator Balances:*")
			hasBalances = true
		}
		lines = append(lines, fmt.Sprintf("• Confirmed: %s sats", formatNumber(confirmed)))
	}
	if unconfirmed, ok := getInt(data, "operator_uncomfirmed_balance"); ok {
		if !hasBalances {
			lines = append(lines, "\n*Operator Balances:*")
		}
		lines = append(lines, fmt.Sprintf("• Unconfirmed: %s sats", formatNumber(unconfirmed)))
	}

	hasStats := false
	if intentsCount, ok := getInt(data, "intents_count"); ok && intentsCount > 0 {
		if !hasStats {
			lines = append(lines, "\n*Statistics:*")
			hasStats = true
		}
		lines = append(lines, fmt.Sprintf("• Intents: %d", intentsCount))
	}
	if vtxosSpent, ok := getInt(data, "vtxos_spent"); ok && vtxosSpent > 0 {
		if !hasStats {
			lines = append(lines, "\n*Statistics:*")
			hasStats = true
		}
		lines = append(lines, fmt.Sprintf("• VTXOs Spent: %d", vtxosSpent))
	}
	if newVtxos, ok := getInt(data, "new_vtxos_count"); ok && newVtxos > 0 {
		if !hasStats {
			lines = append(lines, "\n*Statistics:*")
			hasStats = true
		}
		lines = append(lines, fmt.Sprintf("• New VTXOs: %d", newVtxos))
	}
	if boardingInputs, ok := getInt(data, "boarding_inputs"); ok && boardingInputs > 0 {
		if !hasStats {
			lines = append(lines, "\n*Statistics:*")
			hasStats = true
		}
		lines = append(lines, fmt.Sprintf("• Boarding Inputs: %d", boardingInputs))
	}
	if collabExits, ok := getInt(data, "collab_exits_count"); ok && collabExits > 0 {
		if !hasStats {
			lines = append(lines, "\n*Statistics:*")
		}
		lines = append(lines, fmt.Sprintf("• Collaborative Exits: %d", collabExits))
	}

	if latency, ok := getInt(data, "latency_seconds"); ok {
		lines = append(lines, fmt.Sprintf("\n*Duration:* %d seconds", latency))
	}

	return lines
}

func formatArkTxAlert(data map[string]interface{}) []string {
	var lines []string

	if txid, ok := data["txid"].(string); ok {
		lines = append(lines, fmt.Sprintf("*Ark TX:* `%s`", txid))
	}

	if spentVtxos, ok := getInt(data, "spent_vtxos"); ok && spentVtxos > 0 {
		lines = append(lines, fmt.Sprintf("• VTXOs Spent: %d", spentVtxos))
	}
	if newVtxos, ok := getInt(data, "new_vtxos_count"); ok && newVtxos > 0 {
		lines = append(lines, fmt.Sprintf("• New VTXOs: %d", newVtxos))
	}

	return lines
}

func formatGenericAlert(data map[string]interface{}) []string {
	var lines []string
	for key, value := range data {
		lines = append(lines, fmt.Sprintf("• %s: %v", key, value))
	}
	return lines
}

func getInt(data map[string]interface{}, key string) (int, bool) {
	if val, ok := data[key]; ok {
		if intVal, ok := val.(int); ok {
			return intVal, true
		}
	}
	return 0, false
}

func formatNumber(n int) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result []byte
	for i, digit := range []byte(str) {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, digit)
	}
	return string(result)
}
