package e2e_test

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	"github.com/stretchr/testify/require"
)

// BatchSettleConfig holds configuration parameters for the batch settlement test
type BatchSettleConfig struct {
	NumClients             int    // Number of clients to participate in the batch
	AmountPerVtxo          uint64 // Amount in satoshis per VTXO
	MinParticipantsPerRound int    // Minimum number of participants per round (ARKD_ROUND_MIN_PARTICIPANTS_COUNT)
	MaxParticipantsPerRound int    // Maximum number of participants per round (ARKD_ROUND_MAX_PARTICIPANTS_COUNT)
}

// Command-line flags for test configuration
var numClients = flag.Int("num-clients", 5, "Number of clients to participate in the batch")

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
	
	// Configuration - adjust these values as needed
	config := BatchSettleConfig{
		NumClients:             *numClients, // Number of clients participating (from command-line flag)
		AmountPerVtxo:          10000,       // 10,000 satoshis per VTXO
		MinParticipantsPerRound: 1,          // Default minimum participants per round
		MaxParticipantsPerRound: 128,        // Default maximum participants per round
	}
	
	t.Logf("Running test with %d clients", config.NumClients)
	
	// Run the test with the specified configuration
	runBatchSettleTest(t, config)
}

// runBatchSettleTest runs a test with multiple clients registering VTXOs in a single batch
func runBatchSettleTest(t *testing.T, config BatchSettleConfig) {
	ctx := context.Background()
	
	// Create clients
	clients := make([]arksdk.ArkClient, config.NumClients)
	grpcClients := make([]client.TransportClient, config.NumClients)
	addresses := make([]string, config.NumClients)
	boardingAddresses := make([]string, config.NumClients)
	
	// Setup clients
	for i := 0; i < config.NumClients; i++ {
		client, grpcClient := setupArkSDK(t)
		defer client.Stop()
		defer grpcClient.Close()
		
		clients[i] = client
		grpcClients[i] = grpcClient
		
		// Generate receiving address for each client
		_, addr, boardingAddr, err := client.Receive(ctx)
		require.NoError(t, err)
		addresses[i] = addr
		boardingAddresses[i] = boardingAddr
		
		// Fund each client with a single on-chain transaction
		_, err = runCommand("nigiri", "faucet", boardingAddr, fmt.Sprintf("%.8f", float64(config.AmountPerVtxo)/100000000))
		require.NoError(t, err)
		
		// Only log every 5th client when there are many clients to reduce log spam
		if config.NumClients < 20 || i % 5 == 0 {
			t.Logf("Client %d funded with %.8f BTC", i, float64(config.AmountPerVtxo)/100000000)
		}
	}
	
	// Wait for funds to be confirmed - longer wait for more clients
	t.Log("Waiting for funds to be confirmed...")
	waitTime := 5 * time.Second
	if config.NumClients > 20 {
		waitTime = 10 * time.Second
	}
	if config.NumClients > 40 {
		waitTime = 15 * time.Second
	}
	t.Logf("Waiting %v for funds to be confirmed...", waitTime)
	time.Sleep(waitTime)
	
	// Set up notification handlers for all clients
	notifyWg := &sync.WaitGroup{}
	for i, client := range clients {
		notifyWg.Add(1)
		go func(idx int, c arksdk.ArkClient) {
			defer notifyWg.Done()
			vtxos, err := c.NotifyIncomingFunds(ctx, addresses[idx])
			require.NoError(t, err)
			require.NotEmpty(t, vtxos)
			
			// Only log every 5th client when there are many clients to reduce log spam
			if config.NumClients < 20 || idx % 5 == 0 {
				t.Logf("Client %d received notification of incoming funds", idx)
			}
		}(i, client)
	}
	
	// Log the round participant limits
	t.Logf("Round participant limits: min=%d, max=%d, clients=%d", 
		config.MinParticipantsPerRound, config.MaxParticipantsPerRound, config.NumClients)
	
	// Verify that the test configuration makes sense
	if config.NumClients > config.MaxParticipantsPerRound {
		t.Logf("WARNING: NumClients (%d) exceeds MaxParticipantsPerRound (%d). Some clients may not join the same batch.", 
			config.NumClients, config.MaxParticipantsPerRound)
	}
	
	// All clients settle in the same batch
	t.Log("All clients settling in the same batch...")
	settleWg := &sync.WaitGroup{}
	roundIDs := make([]string, config.NumClients)
	errs := make([]error, config.NumClients)
	
	// Start settlement for all clients simultaneously
	for i, client := range clients {
		settleWg.Add(1)
		go func(idx int, c arksdk.ArkClient) {
			defer settleWg.Done()
			roundID, err := c.Settle(ctx)
			roundIDs[idx] = roundID
			errs[idx] = err
			
			// Only log every 5th client when there are many clients to reduce log spam
			if config.NumClients < 20 || idx % 5 == 0 {
				t.Logf("Client %d initiated settlement", idx)
			}
		}(i, client)
	}
	
	// Wait for all settlements to complete
	settleWg.Wait()
	
	// Check for errors and verify round IDs
	for i, err := range errs {
		require.NoError(t, err, "Client %d settlement failed", i)
		require.NotEmpty(t, roundIDs[i], "Client %d got empty round ID", i)
	}
	
	// Check if all clients should be in the same round based on MaxParticipantsPerRound
	expectSameRound := config.NumClients <= config.MaxParticipantsPerRound
	
	if expectSameRound {
		// Verify all clients are in the same round (have the same round ID)
		for i := 1; i < config.NumClients; i++ {
			require.Equal(t, roundIDs[0], roundIDs[i], "Client %d has different round ID than client 0", i)
		}
		t.Log("All clients are in the same settlement round as expected")
	} else {
		// Count how many different round IDs we have
		roundIDMap := make(map[string]int)
		for _, id := range roundIDs {
			if id != "" {
				roundIDMap[id]++
			}
		}
		t.Logf("Clients were split across %d different rounds due to MaxParticipantsPerRound limit", len(roundIDMap))
		
		// Verify that no round exceeds MaxParticipantsPerRound
		for id, count := range roundIDMap {
			require.LessOrEqual(t, count, config.MaxParticipantsPerRound, 
				"Round %s has %d participants, exceeding the maximum of %d", 
				id, count, config.MaxParticipantsPerRound)
		}
	}
	
	// Wait for notifications to complete
	t.Log("Waiting for notifications to complete...")
	notifyWg.Wait()
	
	// Wait for settlement to complete - longer wait for more clients
	settlementWaitTime := 5 * time.Second
	if config.NumClients > 20 {
		settlementWaitTime = 10 * time.Second
	}
	if config.NumClients > 40 {
		settlementWaitTime = 15 * time.Second
	}
	t.Logf("Waiting %v for settlement to complete...", settlementWaitTime)
	time.Sleep(settlementWaitTime)
	
	// Verify VTXOs for each client
	for i, client := range clients {
		vtxos, _, err := client.ListVtxos(ctx)
		require.NoError(t, err)
		
		// Only log every 5th client when there are many clients to reduce log spam
		if config.NumClients < 20 || i % 5 == 0 {
			t.Logf("Client %d has %d VTXOs after batch settlement", i, len(vtxos))
		}
		require.NotEmpty(t, vtxos)
		
		// Verify the VTXO has the correct round ID
		found := false
		for _, vtxo := range vtxos {
			if len(vtxo.CommitmentTxids) > 0 && vtxo.CommitmentTxids[0] == roundIDs[i] {
				found = true
				break
			}
		}
		require.True(t, found, "Client %d does not have a VTXO with the correct round ID", i)
	}
	
	t.Log("All clients successfully registered VTXOs in a single batch")
}
