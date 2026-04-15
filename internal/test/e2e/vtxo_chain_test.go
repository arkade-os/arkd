package e2e_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	arksdk "github.com/arkade-os/arkd/pkg/client-lib"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/store"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var (
	chainLength   = flag.Int("chain-length", 10, "Number of self-send hops in the VTXO chain")
	initialAmount = flag.Int("initial-amount", 1000, "Initial funding amount in satoshis")
	arkServerUrl  = flag.String("server-url", serverUrl, "Ark server gRPC address")
	arkAdminUrl   = flag.String("admin-url", adminUrl, "Ark admin HTTP address")
	walletSeed    = flag.String("seed", "", "Wallet private key hex (random if empty)")
	skipChain     = flag.Bool("skip-chain", false, "Skip chain creation, only run GetVtxoChain on existing wallet")
)

// TestVtxoChain creates a long VTXO chain by repeatedly self-sending.
// Run with:
//
//	go test -v -run TestVtxoChain -args -chain-length=50 -initial-amount=10000
func TestVtxoChain(t *testing.T) {
	if !flag.Parsed() {
		flag.Parse()
	}

	ctx := t.Context()

	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	require.NoError(t, err)

	client, err := arksdk.NewArkClient(appDataStore)
	require.NoError(t, err)
	t.Cleanup(client.Stop)

	seed := *walletSeed
	if seed == "" {
		privkey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		seed = hex.EncodeToString(privkey.Serialize())
	}
	t.Logf("wallet seed: %s", seed)

	err = client.Init(ctx, arksdk.InitArgs{
		WalletType:  arksdk.SingleKeyWallet,
		ServerUrl:   *arkServerUrl,
		Password:    password,
		Seed:        seed,
		ExplorerURL: explorerUrl,
	})
	require.NoError(t, err)

	err = client.Unlock(ctx, password)
	require.NoError(t, err)

	_, offchainAddr, _, err := client.Receive(ctx)
	require.NoError(t, err)

	if !*skipChain {
		// Fund the client offchain via admin note.
		note := chainGenerateNote(t, uint64(*initialAmount))

		wg := &sync.WaitGroup{}
		var notifyErr error
		wg.Go(func() {
			_, notifyErr = client.NotifyIncomingFunds(ctx, offchainAddr.Address)
		})

		redeemTxid, err := client.RedeemNotes(ctx, []string{note})
		require.NoError(t, err)
		require.NotEmpty(t, redeemTxid)

		wg.Wait()
		require.NoError(t, notifyErr)

		time.Sleep(time.Second)

		spendable, _, err := client.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, spendable, "no spendable VTXOs after faucet")

		start := time.Now()
		hops := 0

		for i := range *chainLength {
			spendable, _, err = client.ListVtxos(ctx)
			require.NoError(t, err)
			for len(spendable) == 0 {
				spendable, _, err = client.ListVtxos(ctx)
				require.NoError(t, err)
			}
			require.Len(t, spendable, 1)
			tip := spendable[0]

			wg := &sync.WaitGroup{}
			var notifyErr error
			wg.Go(func() {
				_, notifyErr = client.NotifyIncomingFunds(ctx, offchainAddr.Address)
			})

			res, err := client.SendOffChain(ctx, []types.Receiver{{
				To:     offchainAddr.Address,
				Amount: tip.Amount,
			}})
			require.NoError(t, err)

			wg.Wait()
			require.NoError(t, notifyErr)

			hops++
			t.Logf("hop %d: txid=%s", i, res.Txid)
		}

		chainElapsed := time.Since(start)
		t.Logf("chain built: %d hops in %s", hops, chainElapsed)

		time.Sleep(2 * time.Second)
	}

	spendable, _, err := client.ListVtxos(ctx)
	require.NoError(t, err)
	tip := spendable[0]

	// Benchmark GetVtxoChain on the last VTXO in the chain.
	last := types.Outpoint{Txid: tip.Txid, VOut: tip.VOut}
	idx, err := grpcindexer.NewClient(*arkServerUrl)
	require.NoError(t, err)

	getChainStart := time.Now()
	resp, err := idx.GetVtxoChain(ctx, last)
	getChainElapsed := time.Since(getChainStart)
	require.NoError(t, err)

	t.Logf("GetVtxoChain: %d entries in %s (tip=%s:%d)", len(resp.Chain), getChainElapsed, last.Txid, last.VOut)
}

func chainGenerateNote(t *testing.T, amount uint64) string {
	t.Helper()

	httpClient := &http.Client{Timeout: 15 * time.Second}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", *arkAdminUrl+"/v1/admin/note", reqBody)
	require.NoError(t, err)

	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var noteResp struct {
		Notes []string `json:"notes"`
	}
	err = json.NewDecoder(resp.Body).Decode(&noteResp)
	require.NoError(t, err)
	require.NotEmpty(t, noteResp.Notes)

	return noteResp.Notes[0]
}
