package e2e_test

import (
	"context"
	"encoding/hex"
	"flag"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	wallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/store"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// TestRateLimitRejectsFastChain enables the velocity rate limiter with a tight
// threshold via the admin API, funds a wallet, then grows a VTXO chain by
// self-sending and asserts the server rejects a hop with a rate-limit error.
//
// Requires the regtest stack (same as TestVtxoChain). Run with:
//
//	go test -v -run TestRateLimitRejectsFastChain -args -smoke
func TestRateLimitRejectsFastChain(t *testing.T) {
	if !flag.Parsed() {
		flag.Parse()
	}
	if !*runSmoke {
		t.Skip("skip rate limit smoke test")
	}

	ctx := t.Context()

	// Enable rate limiting with a very low max velocity so that a single depth
	// gained over a few seconds is enough to exceed it. Restore the default
	// (disabled) afterwards so other smoke tests are unaffected.
	setRateLimit(t, true, 0.001, 3600)
	t.Cleanup(func() { setRateLimit(t, false, 0.28, 3600) })

	appDataStore, err := store.NewStore(store.Config{ConfigStoreType: types.InMemoryStore})
	require.NoError(t, err)

	client, err := wallet.NewWallet(appDataStore)
	require.NoError(t, err)
	t.Cleanup(client.Stop)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	seed := hex.EncodeToString(privkey.Serialize())

	err = client.Init(ctx, wallet.InitArgs{
		ServerUrl:   *arkServerUrl,
		Password:    password,
		Seed:        seed,
		ExplorerURL: explorerUrl,
	})
	require.NoError(t, err)
	require.NoError(t, client.Unlock(ctx, password))

	_, offchainAddr, _, err := client.Receive(ctx)
	require.NoError(t, err)

	// Fund the wallet offchain. Batch settlement is not subject to the offchain
	// rate limiter, so funding always succeeds.
	note := chainGenerateNote(t, uint64(*initialAmount))
	wg := &sync.WaitGroup{}
	var notifyErr error
	wg.Go(func() {
		_, notifyErr = client.NotifyIncomingFunds(ctx, offchainAddr.Address)
	})
	redeemRes, err := client.RedeemNotes(ctx, []string{note})
	require.NoError(t, err)
	require.NotEmpty(t, redeemRes.CommitmentTxid)
	wg.Wait()
	require.NoError(t, notifyErr)

	time.Sleep(time.Second)

	// Grow the chain by self-sending. The first hop spends the depth-0 batch
	// VTXO (delta 0, skipped), but spending a VTXO past its depth-0 marker on a
	// later hop trips the limiter, so a rejection is expected within a few hops.
	var rateLimitErr error
	for i := 0; i < 6 && rateLimitErr == nil; i++ {
		spendable, _, err := client.ListVtxos(ctx)
		require.NoError(t, err)
		if len(spendable) == 0 {
			continue
		}

		var amount uint64
		for _, v := range spendable {
			amount += v.Amount
		}

		notifyCtx, cancelNotify := context.WithCancel(ctx)
		hopWg := &sync.WaitGroup{}
		hopWg.Go(func() {
			_, _ = client.NotifyIncomingFunds(notifyCtx, offchainAddr.Address)
		})

		res, sendErr := client.SendOffChain(ctx, []types.Receiver{{
			To:     offchainAddr.Address,
			Amount: amount,
		}})
		if sendErr != nil {
			cancelNotify()
			hopWg.Wait()
			rateLimitErr = sendErr
			break
		}

		hopWg.Wait()
		cancelNotify()
		t.Logf("hop %d ok: txid=%s", i, res.Txid)
	}

	require.Error(t, rateLimitErr, "expected a rate-limit rejection within a few hops")
	require.Contains(t, strings.ToLower(rateLimitErr.Error()), "rate limit")
}

// setRateLimit updates the velocity rate-limit settings through the admin API.
func setRateLimit(t *testing.T, enabled bool, maxVelocity float64, maxCooldownSecs int64) {
	t.Helper()
	body, err := protojson.Marshal(&arkv1.UpdateSettingsRequest{
		Settings: &arkv1.Settings{
			RateLimitEnabled:         proto.Bool(enabled),
			RateLimitMaxVelocity:     proto.Float64(maxVelocity),
			RateLimitMaxCooldownSecs: proto.Int64(maxCooldownSecs),
		},
	})
	require.NoError(t, err)

	adminHTTPClient := &http.Client{Timeout: 15 * time.Second}
	require.NoError(t, post(
		adminHTTPClient, adminUrl+"/v1/admin/settings", string(body), "updateSettings",
	))
}
