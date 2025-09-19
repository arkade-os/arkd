package e2e_test

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

// multiVtxoConfig holds configuration parameters for the batch settlement test
type multiVtxoConfig struct {
	NumClients              int    // Number of clients to participate in the batch
	AmountPerVtxo           uint64 // Amount in satoshis per VTXO
	MinParticipantsPerRound int    // Minimum number of participants per round (ARKD_ROUND_MIN_PARTICIPANTS_COUNT)
	MaxParticipantsPerRound int    // Maximum number of participants per round (ARKD_ROUND_MAX_PARTICIPANTS_COUNT)
}

// Command-line flags for test configuration
var numClients = flag.Int("num-clients", 5, "Number of clients to participate in the batch")
var runSmoke = flag.Bool("smoke", false, "run smoke tests")

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
	config := multiVtxoConfig{
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
func runBatchSettleTest(t *testing.T, config multiVtxoConfig) {
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
}

type orchestrator struct {
	config  multiVtxoConfig
	clients map[int]arksdk.ArkClient
}

func newOrchestrator(t *testing.T, config multiVtxoConfig) *orchestrator {
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
