package e2e_test

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/arkade-os/arkd/internal/core/application"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/stretchr/testify/require"
)

// singleBatchConfig holds configuration parameters for the batch settlement test
type singleBatchConfig struct {
	NumClients              int    // Number of clients to participate in the batch
	AmountPerVtxo           uint64 // Amount in satoshis per VTXO
	MinParticipantsPerRound int    // Minimum number of participants per round (ARKD_ROUND_MIN_PARTICIPANTS_COUNT)
	MaxParticipantsPerRound int    // Maximum number of participants per round (ARKD_ROUND_MAX_PARTICIPANTS_COUNT)
}

var (
	runSmoke = flag.Bool("smoke", false, "run smoke tests")
	// Command-line flags for test configuration
	numClients = flag.Int("num-clients", 5, "Number of clients to participate in the batch")
	// Regular expressions for parsing logs
	reStats   = regexp.MustCompile(`(?m)round stats:\s*(\{[^\n]+})`)
	reMetrics = regexp.MustCompile(`(?m)round metrics:\s*(\{[^\n]+})`)
	reStages  = regexp.MustCompile(`(?m)round stages:\s*(map\[[^\n]+])`)
	reOps     = regexp.MustCompile(`(?m)round ops:\s*(map\[[^\n]+])`)
)

// TestBatchSettleMultipleClients tests multiple clients registering VTXOs in a single batch
//
// This test verifies that multiple clients can register VTXOs in a single batch settlement round.
// It is affected by the following environment variables:
// - ARKD_ROUND_MIN_PARTICIPANTS_COUNT: Minimum number of participants per round (default: 1)
// - ARKD_ROUND_MAX_PARTICIPANTS_COUNT: Maximum number of participants per round (default: 128)
//
// To run this test with specific round participant limits, set these environment variables before running.
// For example, to test with exactly 5 participants per round:
// ARKD_ROUND_MIN_PARTICIPANTS_COUNT=5 ARKD_ROUND_MAX_PARTICIPANTS_COUNT=5 make run-simulation
//
// To specify the number of clients via command line:
// go test -v -run TestBatchSettleMultipleClients -args -num-clients=8
func TestBatchSettleMultipleClients(t *testing.T) {
	// Parse command-line flags if they haven't been parsed yet
	if !flag.Parsed() {
		flag.Parse()
	}

	if !*runSmoke {
		t.Skip("skip simulation")
	}

	// Configuration - adjust these values as needed
	config := singleBatchConfig{
		NumClients:              *numClients, // Number of clients participating (from command-line flag)
		AmountPerVtxo:           10000,       // 10,000 satoshis per VTXO
		MinParticipantsPerRound: 1,           // Default minimum participants per round
		MaxParticipantsPerRound: 128,         // Default maximum participants per round
	}

	t.Logf("Running test with %d clients", config.NumClients)

	// Run the test with the specified configuration
	runBatchSettleTest(t, config)
}

// runBatchSettleTest runs a test with multiple clients registering VTXOs in a single batch
func runBatchSettleTest(t *testing.T, config singleBatchConfig) {
	clientsManager := newOrchestrator(t, config)

	clientsManager.onboard(t)

	if t.Failed() {
		return
	}

	t.Logf("All clients funded with %.8f BTC", float64(config.AmountPerVtxo)/100000000)

	commitmentTxid := clientsManager.settle(t)

	if t.Failed() {
		return
	}

	t.Logf("All clients settled in batch 0 of commitment tx %s", commitmentTxid)
	t.Logf("Generating report file...")

	report := newReport(commitmentTxid)
	err := report.parseDockerLogs()
	require.NoError(t, err)

	err = report.writeToFile("report.json")
	require.NoError(t, err)

	t.Logf("Generated report file ./report.json")
}

type orchestrator struct {
	config  singleBatchConfig
	clients map[int]arksdk.ArkClient
}

func newOrchestrator(t *testing.T, config singleBatchConfig) *orchestrator {
	chClients := make(chan struct {
		id     int
		client arksdk.ArkClient
	}, config.NumClients)
	clients := make(map[int]arksdk.ArkClient)
	wg := &sync.WaitGroup{}
	wg.Add(config.NumClients)
	go func() {
		for i := range config.NumClients {
			go func(wg *sync.WaitGroup, id int) {
				defer wg.Done()
				client, _ := setupArkSDK(t)
				chClients <- struct {
					id     int
					client arksdk.ArkClient
				}{id, client}
			}(wg, i)
		}
	}()

	go func() {
		for client := range chClients {
			clients[client.id] = client.client
		}
	}()

	wg.Wait()
	close(chClients)

	return &orchestrator{config, clients}
}

func (o *orchestrator) onboard(t *testing.T) {
	out, err := runDockerExec(
		"arkd", "arkd", "note", "--amount", strconv.Itoa(int(o.config.AmountPerVtxo)),
		"--quantity", strconv.Itoa(o.config.NumClients),
	)
	require.NoError(t, err)

	notes := strings.Fields(out)

	chCommitmentTx := make(chan string)
	commitmentTxs := make(map[string]struct{})
	wg := &sync.WaitGroup{}
	wg.Add(o.config.NumClients)

	go func() {
		for i, client := range o.clients {
			note := append([]string{}, notes[i])
			go func(id int, client arksdk.ArkClient, note []string) {
				defer wg.Done()

				txid, err := client.RedeemNotes(context.Background(), note)
				require.NoError(t, err, "client %d failed to redeem note", id)

				t.Logf("Client %d redeemd a note", i)
				chCommitmentTx <- txid
			}(i, client, note)
		}
	}()

	go func() {
		for txid := range chCommitmentTx {
			commitmentTxs[txid] = struct{}{}
		}
	}()

	wg.Wait()
	close(chCommitmentTx)
}

func (o *orchestrator) settle(t *testing.T) string {
	chCommitmentTx := make(chan string)
	commitmentTxs := make(map[string]struct{})
	wg := &sync.WaitGroup{}
	wg.Add(o.config.NumClients)

	go func() {
		for i, client := range o.clients {
			go func(id int, client arksdk.ArkClient) {
				defer wg.Done()

				txid, err := client.Settle(context.Background())
				require.NoError(t, err, "client %d failed to settle funds", id)

				t.Logf("Client %d settled funds", i)
				chCommitmentTx <- txid
			}(i, client)
		}
	}()

	go func() {
		for txid := range chCommitmentTx {
			commitmentTxs[txid] = struct{}{}
		}
	}()

	wg.Wait()
	close(chCommitmentTx)

	require.Len(t, commitmentTxs, 1, fmt.Sprintf("Clients did not settle in the same batch but in %d", len(commitmentTxs)))

	var commitmentTxid string
	for txid := range commitmentTxs {
		commitmentTxid = txid
	}
	return commitmentTxid
}

type report struct {
	Name    string                             `json:"name"`
	Tree    string                             `json:"tree"`
	Stats   *application.RoundStats            `json:"stats,omitempty"`
	Metrics *application.RoundMetrics          `json:"metrics,omitempty"`
	Stages  map[string]application.StageMetric `json:"stages,omitempty"`
	Ops     map[string]application.OpMetric    `json:"ops,omitempty"`
}

func newReport(commitmentTxid string) *report {
	return &report{
		Tree:   fmt.Sprintf("https://tree-query-poc.netlify.app/?fetch=http://localhost:7070/v1/commitmentTx/%s", commitmentTxid),
		Stages: map[string]application.StageMetric{},
		Ops:    map[string]application.OpMetric{},
	}
}

func (r *report) parseDockerLogs() error {
	logs, err := getArkdLogs(context.Background())
	if err != nil {
		return err
	}

	// Find stats
	s := findNthCapture(reStats, logs, 2)
	if s == "" {
		return fmt.Errorf("could not find 2nd occurrence of 'round stats:'")
	}
	body := strings.TrimPrefix(s, "round stats:")
	kv, _ := parseBraceKV(body)
	r.Stats = &application.RoundStats{
		NumIntents:       atoi(kv["NumIntents"]),
		TotalInputVtxos:  atoi(kv["TotalInputVtxos"]),
		TotalOutputVtxos: atoi(kv["TotalOutputVtxos"]),
		NumTreeNodes:     atoi(kv["NumTreeNodes"]),
		CommitmentTxID:   kv["CommitmentTxID"],
	}

	// Set name as 'batch with N clients'
	r.Name = fmt.Sprintf("batch with %d clients", r.Stats.TotalOutputVtxos)

	// Find metrics
	s = findNthCapture(reMetrics, logs, 2)
	if s == "" {
		return fmt.Errorf("could not find 2nd occurrence of 'round metrics:'")
	}
	body = strings.TrimPrefix(s, "round metrics:")
	kv, _ = parseBraceKV(body)
	r.Metrics = &application.RoundMetrics{
		Latency:            atof(kv["Latency"]),
		CPU:                atof(kv["CPU"]),
		CoreEq:             atof(kv["CoreEq"]),
		UtilizedPct:        atof(kv["UtilizedPct"]),
		MemAllocDelta:      atof(kv["MemAllocDelta"]),
		MemSysDelta:        atof(kv["MemSysDelta"]),
		MemTotalAllocDelta: atof(kv["MemTotalAllocDelta"]),
		GCDelta:            uint32(atoi(kv["GCDelta"])),
	}

	// Find stages
	s = findNthCapture(reStages, logs, 2)
	if s == "" {
		return fmt.Errorf("could not find 2nd occurrence of 'round stages:'")
	}
	body = strings.TrimPrefix(s, "round stages:")
	m, _ := parseMapOfStructs(body)
	for k, kv := range m {
		r.Stages[k] = application.StageMetric{Latency: atof(kv["Latency"])}
	}

	// Find ops
	s = findNthCapture(reOps, logs, 2)
	if s == "" {
		return fmt.Errorf("could not find 2nd occurrence of 'round ops:'")
	}
	body = strings.TrimPrefix(s, "round ops:")
	m, _ = parseMapOfStructs(body)
	for k, kv := range m {
		r.Ops[k] = application.OpMetric{
			Latency:            atof(kv["Latency"]),
			CPU:                atof(kv["CPU"]),
			CoreEq:             atof(kv["CoreEq"]),
			UtilizedPct:        atof(kv["UtilizedPct"]),
			MemAllocDelta:      atof(kv["MemAllocDelta"]),
			MemSysDelta:        atof(kv["MemSysDelta"]),
			MemTotalAllocDelta: atof(kv["MemTotalAllocDelta"]),
			GCDelta:            uint32(atoi(kv["GCDelta"])),
		}
	}

	return nil
}

func getArkdLogs(ctx context.Context) (string, error) {
	containerName := "arkd"

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}

	// Inspect to check if TTY is enabled (affects log format)
	inspect, err := cli.ContainerInspect(ctx, containerName)
	if err != nil {
		return "", err
	}
	isTTY := inspect.Config != nil && inspect.Config.Tty

	rc, err := cli.ContainerLogs(ctx, containerName, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     false,
		Timestamps: false,
	})
	if err != nil {
		return "", err
	}
	defer rc.Close()

	var buf bytes.Buffer
	if isTTY {
		// Raw stream, just copy
		_, err = io.Copy(&buf, rc)
	} else {
		// Non-TTY multiplexed stream, demux with stdcopy
		_, err = stdcopy.StdCopy(&buf, &buf, rc)
	}
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (r *report) writeToFile(path string) error {
	return writeJSON(path, r)
}
