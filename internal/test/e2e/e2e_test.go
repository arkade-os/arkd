package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/redemption"
	inmemorystoreconfig "github.com/arkade-os/arkd/pkg/client-lib/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	password         = "password"
	delegateLocktime = arklib.AbsoluteLocktime(10)
)

func TestMain(m *testing.M) {
	if err := generateBlocks(1); err != nil {
		log.Fatalf("error generating block: %s", err)
	}

	err := setupArkd()
	if err != nil {
		log.Fatalf("error setting up server wallet and CLI: %s", err)
	}
	time.Sleep(1 * time.Second)

	code := m.Run()
	os.Exit(code)
}

func TestBatchSession(t *testing.T) {
	// In this test Alice and Bob onboard their funds in the same commitment tx and then
	// refresh their vtxos together in another commitment tx
	t.Run("refresh vtxos", func(t *testing.T) {
		ctx := t.Context()
		alice := setupArkSDK(t)
		bob := setupArkSDK(t)

		_, aliceOffchainAddr, aliceBoardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)
		_, bobOffchainAddr, bobBoardingAddr, err := bob.Receive(ctx)
		require.NoError(t, err)

		// Faucet Alice and Bob boarding addresses
		faucetOnchain(t, aliceBoardingAddr, 0.00021)
		faucetOnchain(t, bobBoardingAddr, 0.00021)
		time.Sleep(6 * time.Second)

		aliceBalance, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.Zero(t, int(aliceBalance.OffchainBalance.Total))
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.NotEmpty(t, aliceBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, int(aliceBalance.OnchainBalance.LockedAmount[0].Amount))

		bobBalance, err := bob.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.Zero(t, int(bobBalance.OffchainBalance.Total))
		require.Empty(t, int(bobBalance.OnchainBalance.SpendableAmount))
		require.NotEmpty(t, bobBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, int(bobBalance.OnchainBalance.LockedAmount[0].Amount))

		wg := &sync.WaitGroup{}
		wg.Add(4)

		// They join the same batch to settle their funds
		var aliceIncomingErr, bobIncomingErr error
		go func() {
			_, aliceIncomingErr = alice.NotifyIncomingFunds(ctx, aliceOffchainAddr)
			wg.Done()
		}()
		go func() {
			_, bobIncomingErr = bob.NotifyIncomingFunds(ctx, bobOffchainAddr)
			wg.Done()
		}()

		var aliceCommitmentTx, bobCommitmentTx string
		var aliceBatchErr, bobBatchErr error
		go func() {
			aliceCommitmentTx, aliceBatchErr = alice.Settle(ctx)
			wg.Done()
		}()
		go func() {
			bobCommitmentTx, bobBatchErr = bob.Settle(ctx)
			wg.Done()
		}()

		wg.Wait()

		require.NoError(t, aliceIncomingErr)
		require.NoError(t, bobIncomingErr)
		require.NoError(t, aliceBatchErr)
		require.NoError(t, bobBatchErr)
		require.NotEmpty(t, aliceCommitmentTx)
		require.NotEmpty(t, bobCommitmentTx)
		require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

		time.Sleep(time.Second)

		aliceBalance, err = alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.NotZero(t, int(aliceBalance.OffchainBalance.Total))

		bobBalance, err = bob.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.NotZero(t, int(bobBalance.OffchainBalance.Total))

		time.Sleep(5 * time.Second)

		// Alice and Bob refresh their VTXOs by joining another batch together
		wg.Add(4)

		go func() {
			_, aliceIncomingErr = alice.NotifyIncomingFunds(ctx, aliceOffchainAddr)
			wg.Done()
		}()
		go func() {
			_, bobIncomingErr = bob.NotifyIncomingFunds(ctx, bobOffchainAddr)
			wg.Done()
		}()

		go func() {
			aliceCommitmentTx, aliceBatchErr = alice.Settle(ctx)
			wg.Done()
		}()
		go func() {
			bobCommitmentTx, bobBatchErr = bob.Settle(ctx)
			wg.Done()
		}()

		wg.Wait()
		time.Sleep(time.Second)

		require.NoError(t, aliceIncomingErr)
		require.NoError(t, bobIncomingErr)
		require.NoError(t, aliceBatchErr)
		require.NoError(t, bobBatchErr)
		require.NotEmpty(t, aliceCommitmentTx)
		require.NotEmpty(t, bobCommitmentTx)
		require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

		aliceBalance, err = alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.NotZero(t, int(aliceBalance.OffchainBalance.Total))
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

		bobBalance, err = bob.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.NotZero(t, int(bobBalance.OffchainBalance.Total))
		require.Zero(t, int(bobBalance.OnchainBalance.SpendableAmount))
		require.Empty(t, bobBalance.OnchainBalance.LockedAmount)
	})

	// In this test Alice redeems 2 notes and then tries to redeem them again to ensure
	// they can be redeeemed only once
	t.Run("redeem notes", func(t *testing.T) {
		alice := setupArkSDK(t)
		_, offchainAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddr)

		balance, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Zero(t, balance.OffchainBalance.Total)
		require.Empty(t, balance.OnchainBalance.LockedAmount)
		require.Zero(t, int(balance.OnchainBalance.SpendableAmount))

		note1 := generateNote(t, 21000)
		note2 := generateNote(t, 2100)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var incomingErr error
		go func() {
			_, incomingErr = alice.NotifyIncomingFunds(t.Context(), offchainAddr)
			wg.Done()
		}()

		commitmentTx, err := alice.RedeemNotes(t.Context(), []string{note1, note2})
		require.NoError(t, err)
		require.NotEmpty(t, commitmentTx)

		wg.Wait()
		require.NoError(t, incomingErr)

		time.Sleep(time.Second)

		balance, err = alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Greater(t, int(balance.OffchainBalance.Total), 21000)
		require.Empty(t, balance.OnchainBalance.LockedAmount)
		require.Zero(t, int(balance.OnchainBalance.SpendableAmount))

		_, err = alice.RedeemNotes(t.Context(), []string{note1})
		require.Error(t, err)
		_, err = alice.RedeemNotes(t.Context(), []string{note2})
		require.Error(t, err)
		_, err = alice.RedeemNotes(t.Context(), []string{note1, note2})
		require.Error(t, err)
	})
}

func TestUnilateralExit(t *testing.T) {
	// In this test Alice owns a leaf VTXO and unrolls it onchain
	t.Run("leaf vtxo", func(t *testing.T) {
		alice := setupArkSDK(t)

		// Faucet 21000 sats offchain and some little amount onchain
		// to cover network fees for the unroll
		faucet(t, alice, 0.00021)
		time.Sleep(5 * time.Second)

		balance, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.NotZero(t, balance.OffchainBalance.Total)
		require.Empty(t, balance.OnchainBalance.LockedAmount)

		err = alice.Unroll(t.Context())
		require.NoError(t, err)

		err = generateBlocks(1)
		require.NoError(t, err)

		time.Sleep(10 * time.Second)

		balance, err = alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Zero(t, balance.OffchainBalance.Total)
		require.NotEmpty(t, balance.OnchainBalance.LockedAmount)
		require.NotZero(t, balance.OnchainBalance.LockedAmount[0].Amount)
	})

	// In this test Bob receives from Alice a VTXO offchain and unrolls it onchain
	t.Run("preconfirmed vtxo", func(t *testing.T) {
		// Faucet Alice
		alice := setupArkSDK(t)
		faucetOffchain(t, alice, 0.001)

		bob := setupArkSDK(t)
		bobOnchainAddr, bobOffchainAddr, _, err := bob.Receive(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, bobOnchainAddr)
		require.NotEmpty(t, bobOffchainAddr)

		bobBalance, err := bob.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.Zero(t, bobBalance.OffchainBalance.Total)
		require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

		// Alice sends to Bob
		wg := &sync.WaitGroup{}
		wg.Add(1)
		var incomingErr error
		go func() {
			_, incomingErr = bob.NotifyIncomingFunds(t.Context(), bobOffchainAddr)
			wg.Done()
		}()
		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 21000,
		}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		time.Sleep(time.Second)

		bobBalance, err = bob.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.NotZero(t, bobBalance.OffchainBalance.Total)
		require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

		// Fund Bob's onchain wallet to cover network fees for the unroll
		faucetOnchain(t, bobOnchainAddr, 0.0001)
		time.Sleep(5 * time.Second)

		// Unroll the whole chain until the checkpoint tx
		err = bob.Unroll(t.Context())
		require.NoError(t, err)

		// Generate some blocks to ensure the checkpoint tx is confirmed
		err = generateBlocks(1)
		require.NoError(t, err)
		time.Sleep(5 * time.Second)
		err = generateBlocks(1)
		require.NoError(t, err)
		time.Sleep(5 * time.Second)

		// Finish the unroll and broadcast the ark tx
		err = bob.Unroll(t.Context())
		require.NoError(t, err)

		err = generateBlocks(1)
		require.NoError(t, err)

		time.Sleep(8 * time.Second)

		// Bob now just needs to wait for the unilateral exit delay to spend the unrolled VTXOs
		bobBalance, err = bob.Balance(t.Context())
		require.NoError(t, err)
		require.Zero(t, bobBalance.OffchainBalance.Total)
		require.NotEmpty(t, bobBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, bobBalance.OnchainBalance.LockedAmount[0].Amount)
	})
}

func TestCollaborativeExit(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		// In this test Alice sends to Bob's onchain address by producing a (VTXO) change
		t.Run("with change", func(t *testing.T) {
			alice := setupArkSDK(t)
			bob := setupArkSDK(t)

			// Faucet Alice
			faucetOffchain(t, alice, 0.001)

			aliceBalance, err := alice.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)

			bobBalance, err := bob.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

			bobOnchainAddr, _, _, err := bob.Receive(t.Context())
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			// Send to Bob's onchain address
			_, err = alice.CollaborativeExit(t.Context(), bobOnchainAddr, 21000)
			require.NoError(t, err)

			time.Sleep(5 * time.Second)

			prevTotalBalance := int(aliceBalance.OffchainBalance.Total)
			aliceBalance, err = alice.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)
			require.Less(
				t,
				int(aliceBalance.OffchainBalance.Total),
				prevTotalBalance,
			)

			bobBalance, err = bob.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)
			require.Equal(t, 21000, int(bobBalance.OnchainBalance.SpendableAmount))
		})

		// In this test Alice sends all to Bob'c onchain address without (VTXO) change
		t.Run("without change", func(t *testing.T) {
			alice := setupArkSDK(t)
			bob := setupArkSDK(t)

			// Faucet Alice
			faucetOffchain(t, alice, 0.00021100) // 21000 + 100 satoshis (amount + fee)

			aliceBalance, err := alice.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)
			require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

			bobBalance, err := bob.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

			bobOnchainAddr, _, _, err := bob.Receive(t.Context())
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			// Send all to Bob's onchain address
			_, err = alice.CollaborativeExit(t.Context(), bobOnchainAddr, 21000)
			require.NoError(t, err)

			time.Sleep(5 * time.Second)

			aliceBalance, err = alice.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Zero(t, int(aliceBalance.OffchainBalance.Total))
			require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

			bobBalance, err = bob.Balance(t.Context())
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			// 100 satoshis is the fee for the onchain output
			require.Equal(t, 21000, int(bobBalance.OnchainBalance.SpendableAmount))
		})
	})

	t.Run("invalid", func(t *testing.T) {
		// In this test Alice funds her boarding address without settling and tries to join a batch
		// funding Bob's onchain address. The server should reject the request
		t.Run("with boarding inputs", func(t *testing.T) {
			alice := setupArkSDK(t)
			bob := setupArkSDK(t)

			_, _, aliceBoardingAddr, err := alice.Receive(t.Context())
			require.NoError(t, err)
			require.NotEmpty(t, aliceBoardingAddr)

			bobOnchainAddr, _, _, err := bob.Receive(t.Context())
			require.NoError(t, err)
			require.NotEmpty(t, aliceBoardingAddr)

			faucetOffchain(t, alice, 0.00021)
			faucetOnchain(t, aliceBoardingAddr, 0.001)
			time.Sleep(5 * time.Second)

			_, err = alice.CollaborativeExit(t.Context(), bobOnchainAddr, 21000)
			require.Error(t, err)

			require.ErrorContains(t, err, "include onchain inputs and outputs")
		})
	})
}

func TestOffchainTx(t *testing.T) {
	// In this test Alice sends several times to Bob to create a chain of offchain txs
	t.Run("chain of txs", func(t *testing.T) {
		ctx := context.Background()
		alice := setupArkSDK(t)
		defer alice.Stop()

		bob := setupArkSDK(t)
		defer bob.Stop()

		faucetOffchain(t, alice, 0.001)

		_, bobAddress, _, err := bob.Receive(ctx)
		require.NoError(t, err)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var incomingFunds []types.Vtxo
		var incomingErr error
		go func() {
			incomingFunds, incomingErr = bob.NotifyIncomingFunds(ctx, bobAddress)
			wg.Done()
		}()
		_, err = alice.SendOffChain(ctx, []types.Receiver{{To: bobAddress, Amount: 1000}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.NotNil(t, incomingFunds)
		time.Sleep(time.Second)

		bobVtxos, _, err := bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 1)

		wg.Add(1)
		go func() {
			incomingFunds, incomingErr = bob.NotifyIncomingFunds(ctx, bobAddress)
			wg.Done()
		}()
		_, err = alice.SendOffChain(ctx, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.NotNil(t, incomingFunds)
		time.Sleep(time.Second)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 2)

		wg.Add(1)
		go func() {
			incomingFunds, incomingErr = bob.NotifyIncomingFunds(ctx, bobAddress)
			wg.Done()
		}()
		_, err = alice.SendOffChain(ctx, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.NotNil(t, incomingFunds)
		time.Sleep(time.Second)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 3)

		wg.Add(1)
		go func() {
			incomingFunds, incomingErr = bob.NotifyIncomingFunds(ctx, bobAddress)
			wg.Done()
		}()
		_, err = alice.SendOffChain(ctx, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.NotNil(t, incomingFunds)
		time.Sleep(time.Second)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 4)

		// bobVtxos should be unique
		uniqueVtxos := make(map[string]struct{})
		for _, v := range bobVtxos {
			uniqueVtxos[fmt.Sprintf("%s:%d", v.Txid, v.VOut)] = struct{}{}
		}
		require.Len(t, uniqueVtxos, len(bobVtxos))
	})

	// In this test Alice sends many times to Bob who then sends all back to Alice in a single
	// offchain tx composed by many checkpoint txs, as the number of the inputs of the ark tx
	t.Run("send with multiple inputs", func(t *testing.T) {
		const numInputs = 5
		const amount = 2100

		alice := setupArkSDK(t)
		bob := setupArkSDK(t)

		_, aliceOffchainAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, aliceOffchainAddr)

		_, bobOffchainAddr, _, err := bob.Receive(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		faucetOffchain(t, alice, 0.001)

		wg := &sync.WaitGroup{}
		for range numInputs {
			wg.Add(1)
			var incomingErr error
			go func() {
				_, incomingErr = alice.NotifyIncomingFunds(t.Context(), aliceOffchainAddr)
				wg.Done()
			}()
			_, err := alice.SendOffChain(t.Context(), []types.Receiver{{
				To:     bobOffchainAddr,
				Amount: amount,
			}})
			require.NoError(t, err)
			wg.Wait()
			require.NoError(t, incomingErr)
			time.Sleep(time.Second)
		}

		wg.Add(1)
		var incomingErr error
		go func() {
			_, incomingErr = alice.NotifyIncomingFunds(t.Context(), aliceOffchainAddr)
			wg.Done()
		}()
		_, err = bob.SendOffChain(t.Context(), []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: numInputs * amount,
		}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
	})

	// In this test Alice sends to Bob a sub-dust VTXO. Bob can't spend or settle his VTXO.
	// He must receive other offchain funds to be able to settle them into a non-sub-dust
	t.Run("sub dust", func(t *testing.T) {
		alice := setupArkSDK(t)
		bob := setupArkSDK(t)

		faucetOffchain(t, alice, 0.00021)

		_, aliceOffchainAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, aliceOffchainAddr)

		_, bobOffchainAddr, _, err := bob.Receive(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		wg := &sync.WaitGroup{}
		wg.Add(1)

		// Alice sends 100 sats to Bob
		var incomingErr error
		go func() {
			_, incomingErr = bob.NotifyIncomingFunds(t.Context(), bobOffchainAddr)
			wg.Done()
		}()

		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 100,
		}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		time.Sleep(time.Second)

		// Bob can't spend his VTXO
		_, err = bob.SendOffChain(t.Context(), []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: 100,
		}})
		require.Error(t, err)

		// Nor he can settle
		_, err = bob.Settle(t.Context())
		require.Error(t, err)

		// Alice sends 250 sats more to Bob, another sub-dust amount
		wg.Add(1)
		go func() {
			_, incomingErr = bob.NotifyIncomingFunds(t.Context(), bobOffchainAddr)
			wg.Done()
		}()

		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 250,
		}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		time.Sleep(time.Second)

		// Bob can now settle
		_, err = bob.Settle(t.Context())
		require.NoError(t, err)
	})

	// In this test, we submit several valid transactions in parallel spending the same vtxo.
	// The server should accept only one of them and reject the others.
	t.Run("concurrent submit txs", func(t *testing.T) {
		ctx := t.Context()
		explorer, err := mempool_explorer.NewExplorer(
			"http://localhost:3000", arklib.BitcoinRegTest,
			mempool_explorer.WithTracker(false),
		)
		require.NoError(t, err)

		_, arkSvc := setupArkSDKWithTransport(t)
		t.Cleanup(func() { arkSvc.Close() })

		privkey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		configStore, err := inmemorystoreconfig.NewConfigStore()
		require.NoError(t, err)

		walletStore, err := inmemorystore.NewWalletStore()
		require.NoError(t, err)

		wallet, err := singlekeywallet.NewBitcoinWallet(configStore, walletStore)
		require.NoError(t, err)

		_, err = wallet.Create(ctx, password, hex.EncodeToString(privkey.Serialize()))
		require.NoError(t, err)

		_, err = wallet.Unlock(ctx, password)
		require.NoError(t, err)

		publicKey := privkey.PubKey()

		serverParams, err := arkSvc.GetInfo(ctx)
		require.NoError(t, err)

		signerPubKeyBytes, err := hex.DecodeString(serverParams.SignerPubKey)
		require.NoError(t, err)

		signerPubKey, err := btcec.ParsePubKey(signerPubKeyBytes)
		require.NoError(t, err)

		// Craft address = a simple forfeit closure (A + S)
		vtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{publicKey, signerPubKey},
				},
			},
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)

		closure := vtxoScript.ForfeitClosures()[0]

		address := arklib.Address{
			HRP:        "tark",
			VtxoTapKey: vtxoTapKey,
			Signer:     signerPubKey,
		}

		bobAddrStr, err := address.EncodeV0()
		require.NoError(t, err)

		// faucet the address 21000 sats
		vtxo := faucetOffchainWithAddress(t, bobAddrStr, 0.00021)

		scriptBytes, err := closure.Script()
		require.NoError(t, err)

		merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
		)
		require.NoError(t, err)

		ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
		require.NoError(t, err)

		tapscript := &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		}
		revealedTapscripts := []string{hex.EncodeToString(merkleProof.Script)}

		checkpointTapscript, err := hex.DecodeString(serverParams.CheckpointTapscript)
		require.NoError(t, err)

		vtxoHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		require.NoError(t, err)

		destinations := []string{
			"5120b9dfec0c7700fbdaa5379941391628e033a62dd17521cac0f9a6d83b3e54e6da",
			"5120b9dfec0c7700fbd89a5379941391628e033a62dd17531cac0f9a6d83b3e54e6d",
			"5120b9dfec0c7700fbd89a5379941391628e033a62dd17531cac0f9a6d83b3e44e6d",
			"5120c9dfec0c7700fbd89a5379941391628e033a62dd17531cac0f9a6d83b3e44e6d",
			"5120c9dfec0c7700fbd89a5379941391628e033a62dd17531cac0f9a6d83b3e44e6d",
			"5120c9dfec0c7700fbd89a5379941391628e033a62dd17531cac0f9a6d83b3e44e6d",
			"5120c9dfec0c7700fbd89a5379941391628e033a62dd17531cac0f9a6d83b3e44e7d",
		}

		type tx struct {
			ark         string
			checkpoints []string
		}

		txs := make([]tx, 0, len(destinations))

		// for each destination, build the associated ark transaction (sending the vtxo to the destination)
		for _, receiver := range destinations {
			pkscript, err := hex.DecodeString(receiver)
			require.NoError(t, err)

			ptx, checkpointsPtx, err := offchain.BuildTxs(
				[]offchain.VtxoInput{
					{
						Outpoint: &wire.OutPoint{
							Hash:  *vtxoHash,
							Index: vtxo.VOut,
						},
						Tapscript:          tapscript,
						Amount:             int64(vtxo.Amount),
						RevealedTapscripts: revealedTapscripts,
					},
				},
				[]*wire.TxOut{
					{
						Value:    int64(vtxo.Amount),
						PkScript: pkscript,
					},
				},
				checkpointTapscript,
			)
			require.NoError(t, err)

			encodedCheckpoints := make([]string, 0, len(checkpointsPtx))
			for _, checkpoint := range checkpointsPtx {
				encoded, err := checkpoint.B64Encode()
				require.NoError(t, err)
				encodedCheckpoints = append(encodedCheckpoints, encoded)
			}

			// sign the ark transaction
			encodedArkTx, err := ptx.B64Encode()
			require.NoError(t, err)
			signedArkTx, err := wallet.SignTransaction(
				ctx,
				explorer,
				encodedArkTx,
			)
			require.NoError(t, err)

			txs = append(txs, tx{
				ark:         signedArkTx,
				checkpoints: encodedCheckpoints,
			})
		}

		doSubmit := func(ctx context.Context, wg *sync.WaitGroup, errChan chan error, ark string, checkpoints []string) {
			defer wg.Done()
			_, _, _, err := arkSvc.SubmitTx(ctx, ark, checkpoints)
			errChan <- err
		}

		// submit all transactions in parallel
		wg := &sync.WaitGroup{}
		wg.Add(len(txs))

		errChan := make(chan error, len(txs))
		for _, tx := range txs {
			go doSubmit(ctx, wg, errChan, tx.ark, tx.checkpoints)
		}

		wg.Wait()

		close(errChan)
		errCount := 0
		successCount := 0
		for err := range errChan {
			if err != nil {
				errCount++
				continue
			}

			successCount++
		}
		require.Equal(t, 1, successCount, fmt.Sprintf("expected 1 success, got %d", successCount))
		require.Equal(
			t,
			len(destinations)-1,
			errCount,
			fmt.Sprintf("expected %d errors, got %d", len(destinations)-1, errCount),
		)
	})

	t.Run("finalize pending tx", func(t *testing.T) {
		ctx := t.Context()
		explorer, err := mempool_explorer.NewExplorer(
			"http://localhost:3000", arklib.BitcoinRegTest,
			mempool_explorer.WithTracker(false),
		)
		require.NoError(t, err)

		alice, aliceWallet, _, arkSvc := setupArkSDKwithPublicKey(t)
		t.Cleanup(func() { alice.Stop() })
		t.Cleanup(func() { arkSvc.Close() })

		vtxo := faucetOffchain(t, alice, 0.00021)

		finalizedPendingTxs, err := alice.FinalizePendingTxs(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, finalizedPendingTxs)

		_, offchainAddresses, _, _, err := aliceWallet.GetAddresses(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddresses)
		offchainAddress := offchainAddresses[0]

		serverParams, err := arkSvc.GetInfo(ctx)
		require.NoError(t, err)

		vtxoScript, err := script.ParseVtxoScript(offchainAddress.Tapscripts)
		require.NoError(t, err)
		forfeitClosures := vtxoScript.ForfeitClosures()
		require.Len(t, forfeitClosures, 1)
		closure := forfeitClosures[0]

		scriptBytes, err := closure.Script()
		require.NoError(t, err)

		_, vtxoTapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)

		merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
		)
		require.NoError(t, err)

		ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
		require.NoError(t, err)

		tapscript := &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		}

		checkpointTapscript, err := hex.DecodeString(serverParams.CheckpointTapscript)
		require.NoError(t, err)

		vtxoHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		require.NoError(t, err)

		addr, err := arklib.DecodeAddressV0(offchainAddress.Address)
		require.NoError(t, err)
		pkscript, err := addr.GetPkScript()
		require.NoError(t, err)

		ptx, checkpointsPtx, err := offchain.BuildTxs(
			[]offchain.VtxoInput{
				{
					Outpoint: &wire.OutPoint{
						Hash:  *vtxoHash,
						Index: vtxo.VOut,
					},
					Tapscript:          tapscript,
					Amount:             int64(vtxo.Amount),
					RevealedTapscripts: offchainAddress.Tapscripts,
				},
			},
			[]*wire.TxOut{
				{
					Value:    int64(vtxo.Amount),
					PkScript: pkscript,
				},
			},
			checkpointTapscript,
		)
		require.NoError(t, err)

		encodedCheckpoints := make([]string, 0, len(checkpointsPtx))
		for _, checkpoint := range checkpointsPtx {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}

		// sign the ark transaction
		encodedArkTx, err := ptx.B64Encode()
		require.NoError(t, err)
		signedArkTx, err := aliceWallet.SignTransaction(
			ctx,
			explorer,
			encodedArkTx,
		)
		require.NoError(t, err)

		txid, _, _, err := arkSvc.SubmitTx(ctx, signedArkTx, encodedCheckpoints)
		require.NoError(t, err)
		require.NotEmpty(t, txid)

		time.Sleep(time.Second)

		var incomingFunds []types.Vtxo
		var incomingErr error
		wg := &sync.WaitGroup{}
		wg.Go(func() {
			incomingFunds, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddress.Address)
		})

		finalizedTxIds, err := alice.FinalizePendingTxs(ctx, nil)
		require.NoError(t, err)
		require.NotEmpty(t, finalizedTxIds)
		require.Equal(t, 1, len(finalizedTxIds))
		require.Equal(t, txid, finalizedTxIds[0])

		wg.Wait()
		require.NoError(t, incomingErr)
		require.NotEmpty(t, incomingFunds)
		require.Len(t, incomingFunds, 1)
		require.Equal(t, txid, incomingFunds[0].Txid)
	})

	// In this test, we ensure that a tx with a too big size gets rejected.
	// TODO: move to unit tests and add also one for RegisterIntent
	t.Run("invalid tx size", func(t *testing.T) {
		ctx := t.Context()
		explorer, err := mempool_explorer.NewExplorer(
			"http://localhost:3000", arklib.BitcoinRegTest,
			mempool_explorer.WithTracker(false),
		)
		require.NoError(t, err)

		alice, aliceWallet, _, arkSvc := setupArkSDKwithPublicKey(t)
		t.Cleanup(func() { alice.Stop() })
		t.Cleanup(func() { arkSvc.Close() })

		vtxo := faucetOffchain(t, alice, 0.00021)

		_, offchainAddresses, _, _, err := aliceWallet.GetAddresses(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddresses)
		offchainAddress := offchainAddresses[0]

		serverParams, err := arkSvc.GetInfo(ctx)
		require.NoError(t, err)

		vtxoScript, err := script.ParseVtxoScript(offchainAddress.Tapscripts)
		require.NoError(t, err)
		forfeitClosures := vtxoScript.ForfeitClosures()
		require.Len(t, forfeitClosures, 1)
		closure := forfeitClosures[0]

		scriptBytes, err := closure.Script()
		require.NoError(t, err)

		_, vtxoTapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)

		merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
		)
		require.NoError(t, err)

		ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
		require.NoError(t, err)

		tapscript := &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		}

		checkpointTapscript, err := hex.DecodeString(serverParams.CheckpointTapscript)
		require.NoError(t, err)

		vtxoHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		require.NoError(t, err)

		require.NoError(t, err)

		n := 20_000
		opRetData := [20_000]byte{}

		// Script: OP_RETURN (0x6a) + OP_PUSHDATA2 (0x4d) + len(2 bytes LE) + data
		opRetScript := make([]byte, 0, 1+1+2+n)
		opRetScript = append(opRetScript, 0x6a)                            // OP_RETURN
		opRetScript = append(opRetScript, 0x4d)                            // OP_PUSHDATA2
		opRetScript = append(opRetScript, byte(n&0xff), byte((n>>8)&0xff)) // little-endian length
		opRetScript = append(opRetScript, opRetData[:]...)

		ptx, checkpointsPtx, err := offchain.BuildTxs(
			[]offchain.VtxoInput{
				{
					Outpoint: &wire.OutPoint{
						Hash:  *vtxoHash,
						Index: vtxo.VOut,
					},
					Tapscript:          tapscript,
					Amount:             int64(vtxo.Amount),
					RevealedTapscripts: offchainAddress.Tapscripts,
				},
			},
			[]*wire.TxOut{
				{
					Value:    int64(vtxo.Amount),
					PkScript: opRetScript,
				},
			},
			checkpointTapscript,
		)
		require.NoError(t, err)

		encodedCheckpoints := make([]string, 0, len(checkpointsPtx))
		for _, checkpoint := range checkpointsPtx {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}

		// sign the ark transaction
		encodedArkTx, err := ptx.B64Encode()
		require.NoError(t, err)
		signedArkTx, err := aliceWallet.SignTransaction(
			ctx,
			explorer,
			encodedArkTx,
		)
		require.NoError(t, err)

		txid, finalArkTx, signedCheckpoints, err := arkSvc.SubmitTx(
			ctx, signedArkTx, encodedCheckpoints,
		)
		require.Error(t, err)
		require.Empty(t, txid)
		require.Empty(t, finalArkTx)
		require.Empty(t, signedCheckpoints)
	})
}

// TestDelegateRefresh tests the case where Alice owns a vtxo and delegates Bob to refresh it.
// Alice creates and signs an intent that specifies how the vtxo is refreshed.
// Alice also creates and signs a forfeit transaction using SIGHASH_ALL | ANYONECANPAY,
// so that Bob can later add the connector to the inputs, sign the tx with SIGHASH_ALL,
// and complete the refresh by joining a batch.
func TestDelegateRefresh(t *testing.T) {
	ctx := t.Context()
	alice, _, alicePubKey, grpcClient := setupArkSDKwithPublicKey(t)
	defer alice.Stop()
	defer grpcClient.Close()

	_, aliceAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceAddr)

	aliceArkAddr, err := arklib.DecodeAddressV0(aliceAddr)
	require.NoError(t, err)
	require.NotNil(t, aliceArkAddr)

	bobWallet, bobPubKey, err := setupWalletService(t)
	require.NoError(t, err)
	require.NotNil(t, bobWallet)
	require.NotNil(t, bobPubKey)

	bobTreeSigner, err := bobWallet.NewVtxoTreeSigner(ctx, "m/0/1")
	require.NoError(t, err)
	require.NotNil(t, bobTreeSigner)

	aliceConfig, err := alice.GetConfigData(t.Context())
	require.NoError(t, err)

	signerPubKey := aliceConfig.SignerPubKey

	collaborativeAliceBobClosure := &script.CLTVMultisigClosure{
		Locktime: delegateLocktime,
		MultisigClosure: script.MultisigClosure{
			// both alice and bob must sign the transaction
			PubKeys: []*btcec.PublicKey{alicePubKey, bobPubKey, signerPubKey},
		},
	}

	exitLocktime := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeBlock,
		Value: 10,
	}

	delegationVtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			// delegation script
			collaborativeAliceBobClosure,
			// classic collaborative closure, alice only
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{alicePubKey, signerPubKey},
			},
			// alice exit script
			&script.CSVMultisigClosure{
				Locktime: exitLocktime,
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{alicePubKey},
				},
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := delegationVtxoScript.TapTree()
	require.NoError(t, err)

	arkAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     signerPubKey,
	}

	arkAddressStr, err := arkAddress.EncodeV0()
	require.NoError(t, err)

	// Faucet Alice
	faucetOffchain(t, alice, 0.00021)

	// Move all her funds to the new address including the delegate script path.
	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingFunds []types.Vtxo
	var incomingErr error
	go func() {
		incomingFunds, incomingErr = alice.NotifyIncomingFunds(ctx, arkAddressStr)
		wg.Done()
	}()
	_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
		To:     arkAddressStr,
		Amount: 21000,
	}})
	require.NoError(t, err)

	wg.Wait()
	require.NoError(t, incomingErr)
	require.NotEmpty(t, incomingFunds)

	aliceVtxo := incomingFunds[0]

	// Alice creates the intent that delegate will register
	intentMessage := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		CosignersPublicKeys: []string{bobTreeSigner.GetPublicKey()},
		ValidAt:             0,
		ExpireAt:            0,
	}

	encodedIntentMessage, err := intentMessage.Encode()
	require.NoError(t, err)

	vtxoHash, err := chainhash.NewHashFromStr(aliceVtxo.Txid)
	require.NoError(t, err)

	exitScript, err := delegationVtxoScript.ExitClosures()[0].Script()
	require.NoError(t, err)

	exitScriptMerkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(exitScript).TapHash(),
	)
	require.NoError(t, err)

	sequence, err := arklib.BIP68Sequence(exitLocktime)
	require.NoError(t, err)

	delegatePkScript, err := arkAddress.GetPkScript()
	require.NoError(t, err)

	alicePkScript, err := aliceArkAddr.GetPkScript()
	require.NoError(t, err)

	// It's important the intent doesn't expire or that it does so in a reasonable time,
	// to implement some sort of deadline for the delegate to register it if needed.
	// In this test the intent never expires for the sake of demonstration
	intentProof, err := intent.New(
		encodedIntentMessage,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  *vtxoHash,
					Index: aliceVtxo.VOut,
				},
				Sequence: sequence,
				WitnessUtxo: &wire.TxOut{
					Value:    int64(aliceVtxo.Amount),
					PkScript: delegatePkScript,
				},
			},
		},
		[]*wire.TxOut{
			{
				Value:    int64(aliceVtxo.Amount),
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)

	tapLeafScript := &psbt.TaprootTapLeafScript{
		ControlBlock: exitScriptMerkleProof.ControlBlock,
		Script:       exitScriptMerkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	intentProof.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeafScript}
	intentProof.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeafScript}

	scripts, err := delegationVtxoScript.Encode()
	require.NoError(t, err)

	tapTree := txutils.TapTree(scripts)

	err = txutils.SetArkPsbtField(&intentProof.Packet, 1, txutils.VtxoTaprootTreeField, tapTree)
	require.NoError(t, err)

	unsignedIntentProof, err := intentProof.B64Encode()
	require.NoError(t, err)

	// Alice signs the intent
	signedIntentProof, err := alice.SignTransaction(ctx, unsignedIntentProof)
	require.NoError(t, err)

	signedIntentProofPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedIntentProof), true)
	require.NoError(t, err)

	encodedIntentProof, err := signedIntentProofPsbt.B64Encode()
	require.NoError(t, err)

	// Alice creates a forfeit transaction spending the vtxo with SIGHASH_ALL | ANYONECANPAY
	forfeitOutputAddr, err := btcutil.DecodeAddress(aliceConfig.ForfeitAddress, nil)
	require.NoError(t, err)

	forfeitOutputScript, err := txscript.PayToAddrScript(forfeitOutputAddr)
	require.NoError(t, err)

	connectorAmount := aliceConfig.Dust

	partialForfeitTx, err := tree.BuildForfeitTxWithOutput(
		[]*wire.OutPoint{{
			Hash:  *vtxoHash,
			Index: aliceVtxo.VOut,
		}},
		[]uint32{wire.MaxTxInSequenceNum - 1},
		[]*wire.TxOut{{
			Value:    int64(aliceVtxo.Amount),
			PkScript: delegatePkScript,
		}},
		&wire.TxOut{
			Value:    int64(aliceVtxo.Amount + connectorAmount),
			PkScript: forfeitOutputScript,
		},
		uint32(delegateLocktime),
	)
	require.NoError(t, err)

	updater, err := psbt.NewUpdater(partialForfeitTx)
	require.NoError(t, err)
	require.NotNil(t, updater)

	err = updater.AddInSighashType(txscript.SigHashAnyOneCanPay|txscript.SigHashAll, 0)
	require.NoError(t, err)

	aliceBobScript, err := collaborativeAliceBobClosure.Script()
	require.NoError(t, err)

	aliceBobMerkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(aliceBobScript).TapHash(),
	)
	require.NoError(t, err)

	aliceBobTapLeafScript := &psbt.TaprootTapLeafScript{
		ControlBlock: aliceBobMerkleProof.ControlBlock,
		Script:       aliceBobMerkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	updater.Upsbt.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{aliceBobTapLeafScript}

	b64partialForfeitTx, err := updater.Upsbt.B64Encode()
	require.NoError(t, err)

	signedPartialForfeitTx, err := alice.SignTransaction(ctx, b64partialForfeitTx)
	require.NoError(t, err)

	// 10 blocks later, Bob registers Alice's intent, signs the tree and submit,
	// completes the forfeit tx by adding the connector, signs and finally submits it to complete
	// the batch session in behalf of Alice
	err = generateBlocks(11)
	require.NoError(t, err)

	intentId, err := grpcClient.RegisterIntent(ctx, encodedIntentProof, encodedIntentMessage)
	require.NoError(t, err)

	topics := arksdk.GetEventStreamTopics(
		[]types.Outpoint{aliceVtxo.Outpoint}, []tree.SignerSession{bobTreeSigner},
	)
	stream, close, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	defer close()

	commitmentTxid, err := arksdk.JoinBatchSession(ctx, stream, &delegateBatchEventsHandler{
		signerSession:    bobTreeSigner,
		partialForfeitTx: signedPartialForfeitTx,
		delegatorWallet:  bobWallet,
		client:           grpcClient,
		forfeitPubKey:    aliceConfig.ForfeitPubKey,
		intentId:         intentId,
	})
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
}

// TestSendToCLTVMultisigClosure shows how to send to an ark address that includes a closure locked
// by an absolute delay (and therefore spendable offchain) and spend from it
func TestSendToCLTVMultisigClosure(t *testing.T) {
	ctx := context.Background()
	indexerSvc := setupIndexer(t)
	alice, grpcAlice := setupArkSDKWithTransport(t)
	defer grpcAlice.Close()

	bobPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	configStore, err := inmemorystoreconfig.NewConfigStore()
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)

	bobWallet, err := singlekeywallet.NewBitcoinWallet(configStore, walletStore)
	require.NoError(t, err)

	_, err = bobWallet.Create(ctx, password, hex.EncodeToString(bobPrivKey.Serialize()))
	require.NoError(t, err)

	_, err = bobWallet.Unlock(ctx, password)
	require.NoError(t, err)

	bobPubKey := bobPrivKey.PubKey()

	// Fund Alice's account
	_, offchainAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	faucetOffchain(t, alice, 0.00021)

	const cltvBlocks = 10
	const sendAmount = 10000

	currentHeight, err := getBlockHeight()
	require.NoError(t, err)

	// Craft Bob's address including the absolute-timelocked closure
	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.CLTVMultisigClosure{
				Locktime: arklib.AbsoluteLocktime(currentHeight + cltvBlocks),
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{bobPubKey, aliceAddr.Signer},
				},
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	bobAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     aliceAddr.Signer,
	}

	scriptBytes, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	bobAddrStr, err := bobAddr.EncodeV0()
	require.NoError(t, err)

	// Send to Bob's address
	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingErr error
	go func() {
		_, incomingErr = alice.NotifyIncomingFunds(ctx, bobAddrStr)
		wg.Done()
	}()
	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()
	require.NoError(t, incomingErr)
	time.Sleep(time.Second)

	spendable, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, spendable)

	// Fetch the virtual transaction to extract the taproot tree
	var virtualTx string
	for _, vtxo := range spendable {
		if vtxo.Txid == txid {
			resp, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Txs)

			virtualTx = resp.Txs[0]
			break
		}
	}
	require.NotEmpty(t, virtualTx)

	virtualPtx, err := psbt.NewFromRawBytes(strings.NewReader(virtualTx), true)
	require.NoError(t, err)

	var bobOutput *wire.TxOut
	var bobOutputIndex uint32
	for i, out := range virtualPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
			bobOutput = out
			bobOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, bobOutput)

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	tapscripts := make([]string, 0, len(vtxoScript.Closures))
	for _, closure := range vtxoScript.Closures {
		script, err := closure.Script()
		require.NoError(t, err)

		tapscripts = append(tapscripts, hex.EncodeToString(script))
	}

	serverParams, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointTapscript, err := hex.DecodeString(serverParams.CheckpointTapscript)
	require.NoError(t, err)

	// Build Bob's transaction spending the VTXO after the absolute locktime expired
	ptx, checkpointsPtx, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  virtualPtx.UnsignedTx.TxHash(),
					Index: bobOutputIndex,
				},
				Tapscript:          tapscript,
				Amount:             bobOutput.Value,
				RevealedTapscripts: tapscripts,
			},
		},
		[]*wire.TxOut{
			{
				Value:    bobOutput.Value,
				PkScript: alicePkScript,
			},
		},
		checkpointTapscript,
	)
	require.NoError(t, err)

	explorer, err := mempool_explorer.NewExplorer(
		"http://localhost:3000", arklib.BitcoinRegTest,
		mempool_explorer.WithTracker(false),
	)
	require.NoError(t, err)

	encodedVirtualTx, err := ptx.B64Encode()
	require.NoError(t, err)

	// Sign the transaction
	signedTx, err := bobWallet.SignTransaction(
		ctx,
		explorer,
		encodedVirtualTx,
	)
	require.NoError(t, err)

	checkpoints := make([]string, 0, len(checkpointsPtx))
	for _, ptx := range checkpointsPtx {
		encoded, err := ptx.B64Encode()
		require.NoError(t, err)
		checkpoints = append(checkpoints, encoded)
	}

	// Submit the tx before the locktime expired should fail
	_, _, _, err = grpcAlice.SubmitTx(ctx, signedTx, checkpoints)
	require.Error(t, err)

	// Generate blocks to pass the timelock
	err = generateBlocks(cltvBlocks)
	require.NoError(t, err)

	// Should succeed now
	txid, _, signedCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, checkpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedCheckpoints))
	for _, checkpoint := range signedCheckpoints {
		finalCheckpoint, err := bobWallet.SignTransaction(ctx, explorer, checkpoint)
		require.NoError(t, err)
		finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
	}

	err = grpcAlice.FinalizeTx(ctx, txid, finalCheckpoints)
	require.NoError(t, err)
}

// TestSendToConditionMultisigClosure shows how to send an ark address that includes a closure
// including a custom condition like the revealing of a preimage
func TestSendToConditionMultisigClosure(t *testing.T) {
	ctx := t.Context()
	indexerSvc := setupIndexer(t)
	alice, grpcAlice := setupArkSDKWithTransport(t)
	defer grpcAlice.Close()

	bobPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	configStore, err := inmemorystoreconfig.NewConfigStore()
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)

	bobWallet, err := singlekeywallet.NewBitcoinWallet(
		configStore,
		walletStore,
	)
	require.NoError(t, err)

	_, err = bobWallet.Create(ctx, password, hex.EncodeToString(bobPrivKey.Serialize()))
	require.NoError(t, err)

	_, err = bobWallet.Unlock(ctx, password)
	require.NoError(t, err)

	bobPubKey := bobPrivKey.PubKey()

	// Fund Alice's account
	_, offchainAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	faucetOffchain(t, alice, 0.00021)

	const sendAmount = 10000

	preimage := make([]byte, 32)
	_, err = rand.Read(preimage)
	require.NoError(t, err)

	sha256Hash := sha256.Sum256(preimage)

	// Craft Bob's address including the revealing of a preimage to spend the coins
	conditionScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SHA256).
		AddData(sha256Hash[:]).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)

	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.ConditionMultisigClosure{
				Condition: conditionScript,
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{bobPubKey, aliceAddr.Signer},
				},
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{bobPubKey, aliceAddr.Signer},
			},
		},
	}

	require.Len(t, vtxoScript.ForfeitClosures(), 2)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	bobAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     aliceAddr.Signer,
	}

	scriptBytes, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	bobAddrStr, err := bobAddr.EncodeV0()
	require.NoError(t, err)

	// Send to Bob's address
	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingErr error
	go func() {
		_, incomingErr = alice.NotifyIncomingFunds(ctx, bobAddrStr)
		defer wg.Done()
	}()

	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()
	require.NoError(t, incomingErr)
	time.Sleep(time.Second)

	spendable, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, spendable)

	// Fetch the virtual transaction to extract the taproot tree
	var virtualTx string
	for _, vtxo := range spendable {
		if vtxo.Txid == txid {
			resp, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Txs)

			virtualTx = resp.Txs[0]
			break
		}
	}
	require.NotEmpty(t, virtualTx)

	virtualPtx, err := psbt.NewFromRawBytes(strings.NewReader(virtualTx), true)
	require.NoError(t, err)

	var bobOutput *wire.TxOut
	var bobOutputIndex uint32
	for i, out := range virtualPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
			bobOutput = out
			bobOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, bobOutput)

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	tapscripts := make([]string, 0, len(vtxoScript.Closures))
	for _, closure := range vtxoScript.Closures {
		script, err := closure.Script()
		require.NoError(t, err)

		tapscripts = append(tapscripts, hex.EncodeToString(script))
	}

	serverParams, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointTapscript, err := hex.DecodeString(serverParams.CheckpointTapscript)
	require.NoError(t, err)

	// Build Bob's transaction spending the VTXO by revealing the preimage
	arkPtx, checkpointsPtx, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  virtualPtx.UnsignedTx.TxHash(),
					Index: bobOutputIndex,
				},
				Amount:             bobOutput.Value,
				Tapscript:          tapscript,
				RevealedTapscripts: tapscripts,
			},
		},
		[]*wire.TxOut{
			{
				Value:    bobOutput.Value,
				PkScript: alicePkScript,
			},
		},
		checkpointTapscript,
	)
	require.NoError(t, err)

	explorer, err := mempool_explorer.NewExplorer(
		"http://localhost:3000", arklib.BitcoinRegTest,
		mempool_explorer.WithTracker(false),
	)
	require.NoError(t, err)

	// Add condition witness to the ark tx that reveals the preimage
	err = txutils.SetArkPsbtField(
		arkPtx,
		0,
		txutils.ConditionWitnessField,
		wire.TxWitness{preimage[:]},
	)
	require.NoError(t, err)

	encodedVirtualTx, err := arkPtx.B64Encode()
	require.NoError(t, err)

	// Sign the transaction
	signedTx, err := bobWallet.SignTransaction(
		ctx,
		explorer,
		encodedVirtualTx,
	)
	require.NoError(t, err)

	checkpoints := make([]string, 0, len(checkpointsPtx))
	for _, ptx := range checkpointsPtx {
		encoded, err := ptx.B64Encode()
		require.NoError(t, err)
		checkpoints = append(checkpoints, encoded)
	}

	// Submit the transaction to the server and finalize
	bobTxid, _, signedCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, checkpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedCheckpoints))
	for _, checkpoint := range signedCheckpoints {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		require.NoError(t, err)

		err = txutils.SetArkPsbtField(
			ptx,
			0,
			txutils.ConditionWitnessField,
			wire.TxWitness{preimage[:]},
		)
		require.NoError(t, err)

		encoded, err := ptx.B64Encode()
		require.NoError(t, err)

		finalCheckpoint, err := bobWallet.SignTransaction(ctx, explorer, encoded)
		require.NoError(t, err)
		finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
	}

	err = grpcAlice.FinalizeTx(ctx, bobTxid, finalCheckpoints)
	require.NoError(t, err)
}

func TestReactToFraud(t *testing.T) {
	t.Run("react to unroll of forfeited vtxos", func(t *testing.T) {
		// In this test Alice refreshes a VTXO and tries to unroll the one just forfeited.
		// The server should react by broadcasting the forfeit tx and claiming the unrolled VTXO before
		// Alice's timelock expires
		t.Run("with batch output", func(t *testing.T) {
			ctx := t.Context()

			indexerSvc := setupIndexer(t)
			sdkClient := setupArkSDK(t)

			_, arkAddr, boardingAddress, err := sdkClient.Receive(ctx)
			require.NoError(t, err)

			faucetOnchain(t, boardingAddress, 0.00021)
			time.Sleep(5 * time.Second)

			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := sdkClient.NotifyIncomingFunds(ctx, arkAddr)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()
			commitmentTxid, err := sdkClient.Settle(ctx)
			require.NoError(t, err)

			wg.Wait()
			time.Sleep(5 * time.Second)

			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := sdkClient.NotifyIncomingFunds(ctx, arkAddr)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()
			_, err = sdkClient.Settle(ctx)
			require.NoError(t, err)

			wg.Wait()
			time.Sleep(time.Second)

			_, spentVtxos, err := sdkClient.ListVtxos(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, spentVtxos)

			var vtxo types.Vtxo
			for _, v := range spentVtxos {
				if !v.Preconfirmed && v.CommitmentTxids[0] == commitmentTxid {
					vtxo = v
					break
				}
			}

			expl, err := mempool_explorer.NewExplorer(
				"http://localhost:3000", arklib.BitcoinRegTest,
				mempool_explorer.WithTracker(false),
			)
			require.NoError(t, err)

			branch, err := redemption.NewRedeemBranch(ctx, expl, indexerSvc, vtxo)
			require.NoError(t, err)

			// The tree we want to unroll contains only one tx, therefore there's only one tx to broadcast.
			// Ideally, there should be a (long) branch of txs to be broadcasted and a loop should be used
			// to publish them from the root of the tree down to the leaf.
			leafTx, err := branch.NextRedeemTx()
			require.NoError(t, err)
			require.NotEmpty(t, leafTx)

			bumpAndBroadcastTx(t, leafTx, expl)

			// Give time to the explorer to track down the broadcasted txs.
			time.Sleep(5 * time.Second)

			// The vtxo is now unrolled and unspent in the Bitcoin mempool.
			spentStatus, err := expl.GetTxOutspends(vtxo.Txid)
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(spentStatus), int(vtxo.VOut))
			require.False(t, spentStatus[vtxo.VOut].Spent)
			require.Empty(t, spentStatus[vtxo.VOut].SpentBy)

			// Include the tx in a block.
			err = generateBlocks(1)
			require.NoError(t, err)

			// Give the server the time to react the fraud.
			time.Sleep(8 * time.Second)

			// Ensure the unrolled vtxo is now spent. The server swept it by broadcasting the forfeit tx.
			spentStatus, err = expl.GetTxOutspends(vtxo.Txid)
			require.NoError(t, err)
			require.NotEmpty(t, spentStatus)
			require.True(t, spentStatus[vtxo.VOut].Spent)
			require.NotEmpty(t, spentStatus[vtxo.VOut].SpentBy)
		})
		// In this test Alice onboards, settles, then exits all, and finally tries to unroll the
		// tree of the forfeited VTXO.
		// The server should react by broadcasting the forfeit tx and claiming the unrolled VTXO before
		// Alice's timelock expires.
		// This test differs from the previous one as here, the commitment tx of the very last
		// settlement doesn't contain any batch output, but just connector and exit outs.
		t.Run("without batch output", func(t *testing.T) {
			ctx := t.Context()

			indexerSvc := setupIndexer(t)
			sdkClient := setupArkSDK(t)

			onchainAddr, arkAddr, boardingAddress, err := sdkClient.Receive(ctx)
			require.NoError(t, err)

			faucetOnchain(t, boardingAddress, 0.00021)
			time.Sleep(5 * time.Second)

			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := sdkClient.NotifyIncomingFunds(ctx, arkAddr)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()
			commitmentTxid, err := sdkClient.Settle(ctx)
			require.NoError(t, err)

			wg.Wait()
			time.Sleep(5 * time.Second)

			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := sdkClient.NotifyIncomingFunds(ctx, arkAddr)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()
			// Exit all without any change, so that no batch output is created in the commitment tx
			_, err = sdkClient.CollaborativeExit(ctx, onchainAddr, 21000)
			require.NoError(t, err)

			wg.Wait()
			time.Sleep(time.Second)

			_, spentVtxos, err := sdkClient.ListVtxos(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, spentVtxos)

			var vtxo types.Vtxo
			for _, v := range spentVtxos {
				if !v.Preconfirmed && v.CommitmentTxids[0] == commitmentTxid {
					vtxo = v
					break
				}
			}

			expl, err := mempool_explorer.NewExplorer(
				"http://localhost:3000", arklib.BitcoinRegTest,
				mempool_explorer.WithTracker(false),
			)
			require.NoError(t, err)

			branch, err := redemption.NewRedeemBranch(ctx, expl, indexerSvc, vtxo)
			require.NoError(t, err)

			// The tree we want to unroll contains only one tx, therefore there's only one tx to broadcast.
			// Ideally, there should be a (long) branch of txs to be broadcasted and a loop should be used
			// to publish them from the root of the tree down to the leaf.
			leafTx, err := branch.NextRedeemTx()
			require.NoError(t, err)
			require.NotEmpty(t, leafTx)

			bumpAndBroadcastTx(t, leafTx, expl)

			// Give time to the explorer to track down the broadcasted txs.
			time.Sleep(5 * time.Second)

			// The vtxo is now unrolled and unspent in the Bitcoin mempool.
			spentStatus, err := expl.GetTxOutspends(vtxo.Txid)
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(spentStatus), int(vtxo.VOut))
			require.False(t, spentStatus[vtxo.VOut].Spent)
			require.Empty(t, spentStatus[vtxo.VOut].SpentBy)

			// Include the tx in a block.
			err = generateBlocks(1)
			require.NoError(t, err)

			// Give the server the time to react the fraud.
			time.Sleep(8 * time.Second)

			// Ensure the unrolled vtxo is now spent. The server swept it by broadcasting the forfeit tx.
			spentStatus, err = expl.GetTxOutspends(vtxo.Txid)
			require.NoError(t, err)
			require.NotEmpty(t, spentStatus)
			require.True(t, spentStatus[vtxo.VOut].Spent)
			require.NotEmpty(t, spentStatus[vtxo.VOut].SpentBy)
		})
	})

	// In these tests Alice spends a VTXO and then tries to unroll it onchain.
	// The server should react by broadcasting the checkpoint amd ark tx preventing Alice to claim
	// the unrolled VTXO before her timelock expires
	t.Run("react to unroll of already spent vtxos", func(t *testing.T) {
		t.Run("default vtxo script", func(t *testing.T) {
			ctx := context.Background()
			indexerSvc := setupIndexer(t)
			sdkClient := setupArkSDK(t)
			defer sdkClient.Stop()

			_, offchainAddress, boardingAddress, err := sdkClient.Receive(ctx)
			require.NoError(t, err)

			faucetOnchain(t, boardingAddress, 0.00021)
			time.Sleep(5 * time.Second)

			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := sdkClient.NotifyIncomingFunds(ctx, offchainAddress)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()

			roundId, err := sdkClient.Settle(ctx)
			require.NoError(t, err)

			wg.Wait()
			time.Sleep(5 * time.Second)

			err = generateBlocks(1)
			require.NoError(t, err)

			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := sdkClient.NotifyIncomingFunds(ctx, offchainAddress)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()

			_, err = sdkClient.SendOffChain(
				ctx, []types.Receiver{{To: offchainAddress, Amount: 1000}},
			)
			require.NoError(t, err)

			wg.Wait()

			time.Sleep(5 * time.Second)

			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := sdkClient.NotifyIncomingFunds(ctx, offchainAddress)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()
			_, err = sdkClient.Settle(ctx)
			require.NoError(t, err)

			wg.Wait()

			_, spentVtxos, err := sdkClient.ListVtxos(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, spentVtxos)

			var vtxo types.Vtxo
			for _, v := range spentVtxos {
				if !v.Preconfirmed && v.CommitmentTxids[0] == roundId {
					vtxo = v
					break
				}
			}
			require.NotEmpty(t, vtxo)

			expl, err := mempool_explorer.NewExplorer(
				"http://localhost:3000", arklib.BitcoinRegTest,
				mempool_explorer.WithTracker(false),
			)
			require.NoError(t, err)

			branch, err := redemption.NewRedeemBranch(ctx, expl, indexerSvc, vtxo)
			require.NoError(t, err)

			for parentTx, err := branch.NextRedeemTx(); err == nil; parentTx, err = branch.NextRedeemTx() {
				bumpAndBroadcastTx(t, parentTx, expl)
			}

			err = generateBlocks(30)
			require.NoError(t, err)

			// Give time for the server to detect and process the fraud
			time.Sleep(5 * time.Second)

			balance, err := sdkClient.Balance(ctx)
			require.NoError(t, err)

			require.Empty(t, balance.OnchainBalance.LockedAmount)
		})

		t.Run("cltv vtxo script", func(t *testing.T) {
			ctx := context.Background()
			indexerSvc := setupIndexer(t)
			alice, arkClient := setupArkSDKWithTransport(t)

			defer alice.Stop()
			defer arkClient.Close()

			bobPrivKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			configStore, err := inmemorystoreconfig.NewConfigStore()
			require.NoError(t, err)

			walletStore, err := inmemorystore.NewWalletStore()
			require.NoError(t, err)

			bobWallet, err := singlekeywallet.NewBitcoinWallet(
				configStore,
				walletStore,
			)
			require.NoError(t, err)

			_, err = bobWallet.Create(ctx, password, hex.EncodeToString(bobPrivKey.Serialize()))
			require.NoError(t, err)

			_, err = bobWallet.Unlock(ctx, password)
			require.NoError(t, err)

			bobPubKey := bobPrivKey.PubKey()

			// Fund Alice's account
			_, offchainAddr, boardingAddress, err := alice.Receive(ctx)
			require.NoError(t, err)

			aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
			require.NoError(t, err)

			faucetOnchain(t, boardingAddress, 0.00021)
			time.Sleep(5 * time.Second)

			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := alice.NotifyIncomingFunds(ctx, offchainAddr)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()
			_, err = alice.Settle(ctx)
			require.NoError(t, err)

			wg.Wait()

			time.Sleep(5 * time.Second)

			spendableVtxos, _, err := alice.ListVtxos(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, spendableVtxos)
			require.Len(t, spendableVtxos, 1)

			vtxoToFraud := spendableVtxos[0]
			initialTreeVtxo := vtxoToFraud

			time.Sleep(5 * time.Second)

			const cltvBlocks = 10
			const sendAmount = 10000

			currentHeight, err := getBlockHeight()
			require.NoError(t, err)

			cltvLocktime := arklib.AbsoluteLocktime(currentHeight + cltvBlocks)
			vtxoScript := script.TapscriptsVtxoScript{
				Closures: []script.Closure{
					&script.CLTVMultisigClosure{
						Locktime: cltvLocktime,
						MultisigClosure: script.MultisigClosure{
							PubKeys: []*btcec.PublicKey{bobPubKey, aliceAddr.Signer},
						},
					},
				},
			}

			vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
			require.NoError(t, err)

			closure := vtxoScript.ForfeitClosures()[0]

			bobAddr := arklib.Address{
				HRP:        "tark",
				VtxoTapKey: vtxoTapKey,
				Signer:     aliceAddr.Signer,
			}

			scriptBytes, err := closure.Script()
			require.NoError(t, err)

			merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
				txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
			)
			require.NoError(t, err)

			ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
			require.NoError(t, err)

			tapscript := &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: merkleProof.Script,
			}

			bobAddrStr, err := bobAddr.EncodeV0()
			require.NoError(t, err)

			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := alice.NotifyIncomingFunds(ctx, offchainAddr)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()

			txid, err := alice.SendOffChain(
				ctx, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
			)
			require.NoError(t, err)
			require.NotEmpty(t, txid)

			wg.Wait()
			time.Sleep(time.Second)

			time.Sleep(2 * time.Second)
			spendable, _, err := alice.ListVtxos(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, spendable)

			var virtualTx string
			for _, vtxo := range spendable {
				if vtxo.Txid == txid {
					resp, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
					require.NoError(t, err)
					require.NotNil(t, resp)
					require.NotEmpty(t, resp.Txs)

					virtualTx = resp.Txs[0]
					break
				}
			}
			require.NotEmpty(t, virtualTx)

			virtualPtx, err := psbt.NewFromRawBytes(strings.NewReader(virtualTx), true)
			require.NoError(t, err)
			require.NotNil(t, virtualPtx)

			var bobOutput *wire.TxOut
			var bobOutputIndex uint32
			for i, out := range virtualPtx.UnsignedTx.TxOut {
				if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
					bobOutput = out
					bobOutputIndex = uint32(i)
					break
				}
			}
			require.NotNil(t, bobOutput)

			alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
			require.NoError(t, err)

			tapscripts := make([]string, 0, len(vtxoScript.Closures))
			for _, closure := range vtxoScript.Closures {
				script, err := closure.Script()
				require.NoError(t, err)

				tapscripts = append(tapscripts, hex.EncodeToString(script))
			}

			infos, err := arkClient.GetInfo(ctx)
			require.NoError(t, err)

			checkpointTapscript, err := hex.DecodeString(infos.CheckpointTapscript)
			require.NoError(t, err)

			ptx, checkpointsPtx, err := offchain.BuildTxs(
				[]offchain.VtxoInput{
					{
						Outpoint: &wire.OutPoint{
							Hash:  virtualPtx.UnsignedTx.TxHash(),
							Index: bobOutputIndex,
						},
						Tapscript:          tapscript,
						Amount:             bobOutput.Value,
						RevealedTapscripts: tapscripts,
					},
				},
				[]*wire.TxOut{
					{
						Value:    bobOutput.Value,
						PkScript: alicePkScript,
					},
				},
				checkpointTapscript,
			)
			require.NoError(t, err)

			explorer, err := mempool_explorer.NewExplorer(
				"http://localhost:3000", arklib.BitcoinRegTest,
				mempool_explorer.WithTracker(false),
			)
			require.NoError(t, err)

			encodedArkTx, err := ptx.B64Encode()
			require.NoError(t, err)

			signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedArkTx)
			require.NoError(t, err)

			checkpoints := make([]string, 0, len(checkpointsPtx))
			for _, ptx := range checkpointsPtx {
				encoded, err := ptx.B64Encode()
				require.NoError(t, err)
				checkpoints = append(checkpoints, encoded)
			}

			// Generate blocks to pass the timelock
			for i := 0; i < cltvBlocks+1; i++ {
				err = generateBlocks(1)
				require.NoError(t, err)
			}

			bobTxid, _, signedCheckpoints, err := arkClient.SubmitTx(
				ctx, signedTx, checkpoints,
			)
			require.NoError(t, err)

			finalCheckpoints := make([]string, 0, len(signedCheckpoints))
			for _, checkpoint := range signedCheckpoints {
				finalCheckpoint, err := bobWallet.SignTransaction(ctx, explorer, checkpoint)
				require.NoError(t, err)
				finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				vtxos, err := alice.NotifyIncomingFunds(ctx, offchainAddr)
				require.NoError(t, err)
				require.NotNil(t, vtxos)
			}()

			err = arkClient.FinalizeTx(ctx, bobTxid, finalCheckpoints)
			require.NoError(t, err)

			wg.Wait()
			time.Sleep(time.Second)

			aliceVtxos, _, err := alice.ListVtxos(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, aliceVtxos)

			found := false

			for _, v := range aliceVtxos {
				if v.Txid == bobTxid && v.VOut == 0 {
					found = true
					break
				}
			}
			require.True(t, found)

			branch, err := redemption.NewRedeemBranch(ctx, explorer, indexerSvc, initialTreeVtxo)
			require.NoError(t, err)

			for parentTx, err := branch.NextRedeemTx(); err == nil; parentTx, err = branch.NextRedeemTx() {
				bumpAndBroadcastTx(t, parentTx, explorer)
			}

			// give time for the server to detect and process the fraud
			err = generateBlocks(30)
			require.NoError(t, err)

			// make sure the vtxo of bob is not redeemed
			// the checkpoint is not the bob's virtual tx
			opt := &indexer.GetVtxosRequestOption{}
			bobScript, err := script.P2TRScript(bobAddr.VtxoTapKey)
			require.NoError(t, err)
			require.NotEmpty(t, bobScript)
			// nolint
			opt.WithScripts([]string{hex.EncodeToString(bobScript)})
			// nolint
			opt.WithSpentOnly()

			resp, err := indexerSvc.GetVtxos(ctx, *opt)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Len(t, resp.Vtxos, 1)

			// make sure the vtxo of alice is not spendable
			aliceVtxos, _, err = alice.ListVtxos(ctx)
			require.NoError(t, err)
			require.NotContains(t, aliceVtxos, vtxoToFraud)
		})
	})
}

func TestSweep(t *testing.T) {
	// This test ensures the server is capable of sweeping a batch output once
	// the timelock to claim the liquidity back expires
	t.Run("batch", func(t *testing.T) {
		alice := setupArkSDK(t)
		defer alice.Stop()

		ctx := t.Context()

		_, offchainAddr, boardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)

		faucetOnchain(t, boardingAddr, 0.00021)
		time.Sleep(5 * time.Second)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var incominFunds []types.Vtxo
		var incomingErr error
		go func() {
			incominFunds, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddr)
			wg.Done()
		}()

		// Settle the boarding utxo to create a new batch output expiring in 20 blocks
		_, err = alice.Settle(ctx)
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.Len(t, incominFunds, 1)
		vtxo := incominFunds[0]

		// Generate 30 blocks to expire the batch output
		err = generateBlocks(30)
		require.NoError(t, err)

		// Wait for server to process the sweep
		time.Sleep(20 * time.Second)

		spendable, _, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spendable, 1)
		require.Equal(t, vtxo.Txid, spendable[0].Txid)
		require.True(t, spendable[0].Swept)
		require.False(t, spendable[0].Spent)

		wg.Add(1)
		go func() {
			_, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddr)
			wg.Done()
		}()

		// Test fund recovery
		txid, err := alice.Settle(ctx, arksdk.WithRecoverableVtxos())
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		time.Sleep(time.Second)

		spendable, spent, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, spendable)
		require.Len(t, spendable, 1)
		require.Len(t, spent, 1)
		require.Equal(t, txid, spent[0].SettledBy)
		require.Equal(t, vtxo.Txid, spent[0].Txid)
		require.True(t, spent[0].Swept)
		require.True(t, spent[0].Spent)
	})

	// This test ensures the server is capable of sweeping a checkpoint output once
	// the timelock to claim it back expires
	t.Run("checkpoint", func(t *testing.T) {
		alice := setupArkSDK(t)
		defer alice.Stop()

		ctx := t.Context()

		_, offchainAddr, boardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)

		faucetOnchain(t, boardingAddr, 0.00021)
		time.Sleep(5 * time.Second)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var incomingFunds []types.Vtxo
		var incomingErr error
		go func() {
			incomingFunds, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddr)
			wg.Done()
		}()

		// settle the boarding utxo
		_, err = alice.Settle(ctx)
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.NotEmpty(t, incomingFunds)
		time.Sleep(time.Second)

		boardedVtxo := incomingFunds[0]

		incomingFunds = nil
		incomingErr = nil
		wg.Add(1)
		go func() {
			incomingFunds, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddr)
			wg.Done()
		}()

		// self-send the VTXO to create a checkpoint output
		firstOffchainTxId, err := alice.SendOffChain(
			ctx,
			[]types.Receiver{{To: offchainAddr, Amount: boardedVtxo.Amount}},
		)
		require.NoError(t, err)
		require.NotEmpty(t, firstOffchainTxId)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.NotEmpty(t, incomingFunds)
		time.Sleep(time.Second)

		// self-send again to create a second checkpoint output
		secondOffchainTxId, err := alice.SendOffChain(
			ctx,
			[]types.Receiver{{To: offchainAddr, Amount: boardedVtxo.Amount}},
		)
		require.NoError(t, err)
		require.NotEmpty(t, secondOffchainTxId)

		// unroll the spent VTXO to put checkpoint onchain
		expl, err := mempool_explorer.NewExplorer(
			"http://localhost:3000", arklib.BitcoinRegTest,
			mempool_explorer.WithTracker(false))
		require.NoError(t, err)

		branch, err := redemption.NewRedeemBranch(ctx, expl, setupIndexer(t), boardedVtxo)
		require.NoError(t, err)

		for parentTx, err := branch.NextRedeemTx(); err == nil; parentTx, err = branch.NextRedeemTx() {
			bumpAndBroadcastTx(t, parentTx, expl)
		}

		// give some time for the server to process the unroll and broadcast the checkpoint
		time.Sleep(5 * time.Second)

		// generate 10 blocks to expire the checkpoint output
		err = generateBlocks(10)
		require.NoError(t, err)

		// give time for the server to process the sweep
		time.Sleep(20 * time.Second)

		// verify that the checkpoint output has been put onchain
		// and that the VTXO has been swept
		spendable, spent, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spent, 2)
		require.Len(t, spendable, 1)

		// find first offchain tx vtxo, must be in spent
		var firstOffchainTxVtxo *types.Vtxo
		var unrolledVtxo *types.Vtxo
		for _, v := range spent {
			switch v.Txid {
			case firstOffchainTxId:
				firstOffchainTxVtxo = &v
			case boardedVtxo.Txid:
				unrolledVtxo = &v
			}
		}
		// should be unrolled, swept and spent
		require.NotNil(t, unrolledVtxo)
		require.True(t, unrolledVtxo.Unrolled)
		require.True(t, unrolledVtxo.Swept)
		require.True(t, unrolledVtxo.Spent)

		// should be spent, swept and not unrolled
		require.NotNil(t, firstOffchainTxVtxo)
		require.True(t, firstOffchainTxVtxo.Swept)
		require.True(t, firstOffchainTxVtxo.Spent)
		require.False(t, firstOffchainTxVtxo.Unrolled)

		// find second offchain tx vtxo, must be in spendable
		secondOffchainTxVtxo := spendable[0]
		require.Equal(t, secondOffchainTxId, secondOffchainTxVtxo.Txid)

		// should be swept but not unrolled nor spent
		require.True(t, secondOffchainTxVtxo.Swept)
		require.False(t, secondOffchainTxVtxo.Unrolled)
		require.False(t, secondOffchainTxVtxo.Spent)
	})

	t.Run("with arkd restart", func(t *testing.T) {
		alice := setupArkSDK(t)
		defer alice.Stop()

		ctx := t.Context()

		_, offchainAddr, boardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)

		faucetOnchain(t, boardingAddr, 0.00021)
		time.Sleep(5 * time.Second)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var incominFunds []types.Vtxo
		var incomingErr error
		go func() {
			incominFunds, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddr)
			wg.Done()
		}()

		// Settle the boarding utxo to create a new batch output expiring in 20 blocks
		_, err = alice.Settle(ctx)
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.Len(t, incominFunds, 1)
		vtxo := incominFunds[0]

		// generate a block to confirm the commitment tx
		err = generateBlocks(1)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// lock/unlock the wallet to restart the sweeper
		err = restartArkd()
		require.NoError(t, err)

		// Generate 30 blocks to expire the batch output
		err = generateBlocks(30)
		require.NoError(t, err)

		// Wait for server to process the sweep
		time.Sleep(20 * time.Second)

		spendable, _, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spendable, 1)
		require.Equal(t, vtxo.Txid, spendable[0].Txid)
		require.True(t, spendable[0].Swept)
		require.False(t, spendable[0].Spent)

		wg.Go(func() {
			_, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddr)
		})

		// Test fund recovery
		txid, err := alice.Settle(ctx, arksdk.WithRecoverableVtxos())
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		time.Sleep(time.Second)

		spendable, spent, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, spendable)
		require.Len(t, spendable, 1)
		require.Len(t, spent, 1)
		require.Equal(t, txid, spent[0].SettledBy)
		require.Equal(t, vtxo.Txid, spent[0].Txid)
		require.True(t, spent[0].Swept)
		require.True(t, spent[0].Spent)
	})

	//  create a batch with 4 VTXOs:
	//  root
	//   .
	//   ├── .
	//   |   ├── alice
	//   |   └── bob
	//   └── .
	//       ├── charlie
	//       └── mike
	// then alice unroll its branch
	// it creates several batch outputs with different expiration times
	// test that first the sweeper is sweeping half of the liquidity first
	// then sweep the remaining liquidity
	t.Run("unrolled batch", func(t *testing.T) {
		ctx := t.Context()

		alice := setupArkSDK(t)
		bob := setupArkSDK(t)
		charlie := setupArkSDK(t)
		mike := setupArkSDK(t)
		aliceNote := generateNote(t, 21000)
		bobNote := generateNote(t, 21000)
		charlieNote := generateNote(t, 21000)
		mikeNote := generateNote(t, 21000)

		wg := &sync.WaitGroup{}
		var aliceErr, bobErr, charlieErr, mikeErr error
		var aliceTxid, bobTxid, charlieTxid, mikeTxid string
		wg.Go(func() {
			aliceTxid, aliceErr = alice.RedeemNotes(ctx, []string{aliceNote})
		})
		wg.Go(func() {
			bobTxid, bobErr = bob.RedeemNotes(ctx, []string{bobNote})
		})
		wg.Go(func() {
			charlieTxid, charlieErr = charlie.RedeemNotes(ctx, []string{charlieNote})
		})
		wg.Go(func() {
			mikeTxid, mikeErr = mike.RedeemNotes(ctx, []string{mikeNote})
		})
		wg.Wait()
		require.NoError(t, aliceErr)
		require.NoError(t, bobErr)
		require.NoError(t, charlieErr)
		require.NoError(t, mikeErr)
		require.NotEmpty(t, aliceTxid)
		require.Equal(t, aliceTxid, bobTxid)
		require.Equal(t, aliceTxid, charlieTxid)
		require.Equal(t, aliceTxid, mikeTxid)

		onchainAddr, _, _, err := alice.Receive(ctx)
		require.NoError(t, err)

		// Faucet onchain addr to cover network fees for the unroll.
		faucetOnchain(t, onchainAddr, 0.01)
		time.Sleep(5 * time.Second)

		balance, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.NotZero(t, balance.OffchainBalance.Total)
		require.Empty(t, balance.OnchainBalance.LockedAmount)

		// confirm the commitment tx (time t)
		// sweeper schedules a sweep task at t+20 blocks
		err = generateBlocks(1)
		require.NoError(t, err)

		err = alice.Unroll(ctx)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// t + 1 to confirm the first unroll tx
		// split the root batch in two, "reset" the CSV
		// sweeper schedules 2 sweep tasks at t+20+1 and t+20+1
		err = generateBlocks(1)
		require.NoError(t, err)

		// give time for the server to process the unroll
		time.Sleep(5 * time.Second)

		// wait 10 blocks to unroll again
		// at this point, batches expires in 11 blocks
		err = generateBlocks(10)
		require.NoError(t, err)

		err = alice.Unroll(ctx)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// split one of the batches in two, "reset" the CSV
		// 1 expires in 10 blocks, the other in 20 blocks
		err = generateBlocks(1)
		require.NoError(t, err)

		// give time for the server to process the unroll
		time.Sleep(2 * time.Second)

		// Generate 11 blocks to expire the first batch outputs
		err = generateBlocks(11)
		require.NoError(t, err)

		// Wait for server to process the sweep
		time.Sleep(20 * time.Second)

		// alice vtxos should not be swept yet
		aliceVtxos, _, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, aliceVtxos, 1)
		require.False(t, aliceVtxos[0].Swept)

		// half of the vtxos must be swept
		nbOfVtxosSwept := 0
		bobVtxos, _, err := bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 1)
		if bobVtxos[0].Swept {
			nbOfVtxosSwept++
		}

		charlieVtxos, _, err := charlie.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, charlieVtxos, 1)
		if charlieVtxos[0].Swept {
			nbOfVtxosSwept++
		}

		mikeVtxos, _, err := mike.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, mikeVtxos, 1)
		if mikeVtxos[0].Swept {
			nbOfVtxosSwept++
		}

		require.Equal(t, nbOfVtxosSwept, 2)

		// generate other blocks to expire the remaining batch outputs
		err = generateBlocks(25)
		require.NoError(t, err)

		// give time for the server to process the sweep
		time.Sleep(35 * time.Second)

		// verify that all vtxos have been swept
		aliceVtxos, _, err = alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, aliceVtxos, 1)
		require.True(t, aliceVtxos[0].Swept)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 1)
		require.True(t, bobVtxos[0].Swept)

		charlieVtxos, _, err = charlie.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, charlieVtxos, 1)
		require.True(t, charlieVtxos[0].Swept)

		mikeVtxos, _, err = mike.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, mikeVtxos, 1)
		require.True(t, mikeVtxos[0].Swept)
	})

	// This test creates an "uneconomical batch", ie. one with an amount too small that makes
	// arkd not capable of sweeping it automatically. For such batches, it's required to call the
	// admin api so that they are swept along with other sweepable funds (connectors used for
	// batches that have been already swept)
	t.Run("force by admin", func(t *testing.T) {
		alice := setupArkSDK(t)
		defer alice.Stop()

		ctx := t.Context()

		_, offchainAddr, boardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)

		// Faucet with a small amount that will result in a dust vtxo after fees
		faucetOnchain(t, boardingAddr, 0.00000330)
		time.Sleep(5 * time.Second)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var incomingFunds []types.Vtxo
		var incomingErr error
		go func() {
			incomingFunds, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddr)
			wg.Done()
		}()

		// Settle the boarding utxo to create a new batch output expiring in 20 blocks
		commitmentTxid, err := alice.Settle(ctx)
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
		require.Len(t, incomingFunds, 1)
		vtxo := incomingFunds[0]

		// Generate 30 blocks to expire the batch output
		err = generateBlocks(30)
		require.NoError(t, err)

		// Wait for server to attempt the sweep (it should fail due to dust amount)
		time.Sleep(25 * time.Second)

		// Verify the vtxo is not swept yet (automatic sweep failed)
		spendable, _, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spendable, 1)
		require.Equal(t, vtxo.Txid, spendable[0].Txid)
		require.False(t, spendable[0].Swept, "vtxo should not be swept automatically")

		// Use admin Sweep RPC to manually sweep the batch
		adminHttpClient := &http.Client{
			Timeout: 15 * time.Second,
		}

		reqBody := bytes.NewReader([]byte(fmt.Sprintf(
			`{"connectors": true, "commitment_txids": ["%s"]}`,
			commitmentTxid,
		)))
		req, err := http.NewRequest("POST", "http://localhost:7071/v1/admin/sweep", reqBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
		req.Header.Set("Content-Type", "application/json")

		resp, err := adminHttpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var sweepResp struct {
			Txid string `json:"txid"`
			Hex  string `json:"hex"`
		}
		err = json.NewDecoder(resp.Body).Decode(&sweepResp)
		require.NoError(t, err)
		require.NotEmpty(t, sweepResp.Txid)
		require.NotEmpty(t, sweepResp.Hex)

		// Wait a bit for the sweep event to be processed
		time.Sleep(5 * time.Second)

		// Verify the vtxo is now marked as swept
		spendable, _, err = alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spendable, 1)
		require.Equal(t, vtxo.Txid, spendable[0].Txid)
		require.True(t, spendable[0].Swept, "vtxo should be swept after manual sweep")
	})
}

// TestCollisionBetweenInRoundAndRedeemVtxo tests for a potential collision between VTXOs that
// could occur due to a race condition between simultaneous Settle and SubmitRedeemTx calls.
// The race condition doesn't consistently reproduce, making the test unreliable in automated test
// suites. Therefore, the test is skipped by default and left here as documentation for future
// debugging and reference.
func TestCollisionBetweenInRoundAndRedeemVtxo(t *testing.T) {
	t.Skip()

	ctx := t.Context()
	alice := setupArkSDK(t)
	bob := setupArkSDK(t)

	faucetOffchain(t, alice, 0.00005)

	_, bobAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	// Test collision when first Settle is called
	type resp struct {
		txid string
		err  error
	}

	ch := make(chan resp, 2)
	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		txid, err := alice.Settle(ctx)
		ch <- resp{txid, err}
	}()
	// SDK Settle call is bit slower than Redeem so we introduce small delay so we make sure Settle is called before Redeem
	// this timeout can vary depending on the environment
	go func() {
		time.Sleep(50 * time.Millisecond)
		defer wg.Done()
		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: bobAddr, Amount: 1000}})
		ch <- resp{txid, err}
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	finalResp := resp{}
	for resp := range ch {
		if resp.err != nil {
			finalResp.err = resp.err
		} else {
			finalResp.txid = resp.txid
		}
	}

	t.Log(finalResp.err)
	require.NotEmpty(t, finalResp.txid)
	require.Error(t, finalResp.err)

}

// TestIntent tests intent registration and deletion functionality
func TestIntent(t *testing.T) {
	t.Run("register and delete", func(t *testing.T) {
		ctx := t.Context()
		alice := setupArkSDK(t)

		// faucet offchain address
		faucetOffchain(t, alice, 0.00021)

		_, offchainAddr, _, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddr)

		aliceVtxos, _, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, aliceVtxos)

		cosignerKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		cosigners := []string{hex.EncodeToString(cosignerKey.PubKey().SerializeCompressed())}
		outs := []types.Receiver{{To: offchainAddr, Amount: 20000}}
		_, err = alice.RegisterIntent(ctx, aliceVtxos, []types.Utxo{}, nil, outs, cosigners)
		require.NoError(t, err)

		// should fail because previous intent spend same vtxos
		_, err = alice.RegisterIntent(ctx, aliceVtxos, []types.Utxo{}, nil, outs, cosigners)
		require.Error(t, err)

		// should delete the intent
		err = alice.DeleteIntent(ctx, aliceVtxos, []types.Utxo{}, nil)
		require.NoError(t, err)

		// should fail because no intent is associated with the vtxos
		err = alice.DeleteIntent(ctx, aliceVtxos, []types.Utxo{}, nil)
		require.Error(t, err)
	})

	t.Run("concurrent register", func(t *testing.T) {
		ctx := t.Context()
		alice := setupArkSDK(t)

		// faucet offchain address
		faucetOffchain(t, alice, 0.00021)

		_, offchainAddr, _, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddr)

		aliceVtxos, _, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, aliceVtxos)

		cosignerKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		cosigners := []string{hex.EncodeToString(cosignerKey.PubKey().SerializeCompressed())}
		outs := []types.Receiver{{To: offchainAddr, Amount: 20000}}
		outsBis := []types.Receiver{
			{To: offchainAddr, Amount: 10000},
			{To: offchainAddr, Amount: 10000},
		}

		wg := &sync.WaitGroup{}
		wg.Add(2)

		errChan := make(chan error, 2)

		doRegister := func(ctx context.Context, wg *sync.WaitGroup, errChan chan error, aliceVtxos []types.Vtxo, outs []types.Receiver, cosigners []string) {
			_, err := alice.RegisterIntent(ctx, aliceVtxos, []types.Utxo{}, nil, outs, cosigners)
			errChan <- err
			wg.Done()
		}

		go doRegister(ctx, wg, errChan, aliceVtxos, outs, cosigners)
		go doRegister(ctx, wg, errChan, aliceVtxos, outsBis, cosigners)

		wg.Wait()

		close(errChan)
		errCount := 0
		successCount := 0
		for err := range errChan {
			if err != nil {
				errCount++
				continue
			}

			successCount++
		}
		require.Equal(t, 1, successCount, fmt.Sprintf("expected 1 success, got %d", successCount))
		require.Equal(t, 1, errCount, fmt.Sprintf("expected 1 error, got %d", errCount))
	})
}

// TestBan tests all supported ban scenarios
func TestBan(t *testing.T) {
	t.Run("failed to submit tree nonces", func(t *testing.T) {
		alice, grpcAlice := setupArkSDKWithTransport(t)
		defer alice.Stop()
		defer grpcAlice.Close()

		// faucet the alice's wallet
		_, aliceAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)
		faucetOffchain(t, alice, 0.001)

		vtxos, _, err := alice.ListVtxos(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		aliceVtxo := vtxos[0]

		// setup a random musig2 tree signer
		secKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		signerSession := tree.NewTreeSignerSession(secKey)

		intentId, err := alice.RegisterIntent(
			t.Context(),
			[]types.Vtxo{aliceVtxo},
			[]types.Utxo{},
			nil,
			[]types.Receiver{
				{
					Amount: aliceVtxo.Amount,
					To:     aliceAddr,
				},
			},
			[]string{signerSession.GetPublicKey()},
		)
		require.NoError(t, err)

		topics := arksdk.GetEventStreamTopics(
			[]types.Outpoint{aliceVtxo.Outpoint}, []tree.SignerSession{signerSession},
		)
		stream, close, err := grpcAlice.GetEventStream(t.Context(), topics)
		require.NoError(t, err)
		defer close()

		handlers := &customBatchEventsHandler{
			onBatchStarted: func(ctx context.Context, event client.BatchStartedEvent) (bool, error) {
				buf := sha256.Sum256([]byte(intentId))
				hashedIntentId := hex.EncodeToString(buf[:])

				if slices.Contains(event.HashedIntentIds, hashedIntentId) {
					err := grpcAlice.ConfirmRegistration(ctx, intentId)
					return false, err
				}

				return true, nil
			},
			onTreeSigningStarted: func(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error) {
				return true, nil // just skip, do not submit nonces
			},
		}

		_, err = arksdk.JoinBatchSession(t.Context(), stream, handlers)
		require.Error(t, err)

		// next settle should fail because the nonce has not been submitted
		_, err = alice.Settle(t.Context())
		require.Error(t, err)

		// send should fail
		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			Amount: aliceVtxo.Amount,
			To:     aliceAddr,
		}})
		require.Error(t, err)
	})

	t.Run("failed to submit tree signatures", func(t *testing.T) {
		alice, grpcAlice := setupArkSDKWithTransport(t)
		defer alice.Stop()
		defer grpcAlice.Close()

		// faucet the alice's wallet
		_, aliceAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)

		faucetOffchain(t, alice, 0.001)
		require.NoError(t, err)

		vtxos, _, err := alice.ListVtxos(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		aliceVtxo := vtxos[0]

		// setup a random musig2 tree signer
		secKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		signerSession := tree.NewTreeSignerSession(secKey)

		intentId, err := alice.RegisterIntent(
			t.Context(),
			[]types.Vtxo{aliceVtxo},
			[]types.Utxo{},
			nil,
			[]types.Receiver{
				{
					Amount: aliceVtxo.Amount,
					To:     aliceAddr,
				},
			},
			[]string{signerSession.GetPublicKey()},
		)
		require.NoError(t, err)

		topics := arksdk.GetEventStreamTopics(
			[]types.Outpoint{aliceVtxo.Outpoint}, []tree.SignerSession{signerSession},
		)
		stream, close, err := grpcAlice.GetEventStream(t.Context(), topics)
		require.NoError(t, err)
		defer close()

		var batchExpiry arklib.RelativeLocktime
		handlers := &customBatchEventsHandler{
			onBatchStarted: func(ctx context.Context, event client.BatchStartedEvent) (bool, error) {
				buf := sha256.Sum256([]byte(intentId))
				hashedIntentId := hex.EncodeToString(buf[:])

				if slices.Contains(event.HashedIntentIds, hashedIntentId) {
					err := grpcAlice.ConfirmRegistration(ctx, intentId)
					batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
					return false, err
				}

				return true, nil
			},
			onTreeSigningStarted: func(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error) {
				myPubkey := signerSession.GetPublicKey()
				if !slices.Contains(event.CosignersPubkeys, myPubkey) {
					return true, nil
				}

				signerPubKey := secKey.PubKey()

				sweepClosure := script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{signerPubKey},
					},
					Locktime: batchExpiry,
				}

				script, err := sweepClosure.Script()
				if err != nil {
					return false, err
				}

				commitmentTx, err := psbt.NewFromRawBytes(
					strings.NewReader(event.UnsignedCommitmentTx),
					true,
				)
				if err != nil {
					return false, err
				}

				batchOutput := commitmentTx.UnsignedTx.TxOut[0]
				batchOutputAmount := batchOutput.Value

				sweepTapLeaf := txscript.NewBaseTapLeaf(script)
				sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
				root := sweepTapTree.RootNode.TapHash()

				if err := signerSession.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
					return false, err
				}

				nonces, err := signerSession.GetNonces()
				if err != nil {
					return false, err
				}

				if err = grpcAlice.SubmitTreeNonces(ctx, event.Id, signerSession.GetPublicKey(), nonces); err != nil {
					return false, err
				}

				return false, nil
			},
			onTreeNoncesAggregated: func(ctx context.Context, event client.TreeNoncesAggregatedEvent) (bool, error) {
				return false, nil // skip sending signatures
			},
		}

		_, err = arksdk.JoinBatchSession(t.Context(), stream, handlers)
		require.Error(t, err)

		// next settle should fail because the signature has not been submitted
		_, err = alice.Settle(t.Context())
		require.Error(t, err)

		// send should fail
		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			Amount: aliceVtxo.Amount,
			To:     aliceAddr,
		}})
		require.Error(t, err)
	})

	t.Run("failed to submit valid tree signatures", func(t *testing.T) {
		alice, grpcAlice := setupArkSDKWithTransport(t)
		defer alice.Stop()
		defer grpcAlice.Close()

		// faucet the alice's wallet
		_, aliceAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)
		faucetOffchain(t, alice, 0.001)
		require.NoError(t, err)

		vtxos, _, err := alice.ListVtxos(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		aliceVtxo := vtxos[0]

		// setup a random musig2 tree signer
		secKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		signerSession := tree.NewTreeSignerSession(secKey)

		intentId, err := alice.RegisterIntent(
			t.Context(),
			[]types.Vtxo{aliceVtxo},
			[]types.Utxo{},
			nil,
			[]types.Receiver{
				{
					Amount: aliceVtxo.Amount,
					To:     aliceAddr,
				},
			},
			[]string{signerSession.GetPublicKey()},
		)
		require.NoError(t, err)

		topics := arksdk.GetEventStreamTopics(
			[]types.Outpoint{aliceVtxo.Outpoint}, []tree.SignerSession{signerSession},
		)
		stream, close, err := grpcAlice.GetEventStream(t.Context(), topics)
		require.NoError(t, err)
		defer close()

		handlers := &customBatchEventsHandler{
			onBatchStarted: func(ctx context.Context, event client.BatchStartedEvent) (bool, error) {
				buf := sha256.Sum256([]byte(intentId))
				hashedIntentId := hex.EncodeToString(buf[:])

				if slices.Contains(event.HashedIntentIds, hashedIntentId) {
					err := grpcAlice.ConfirmRegistration(ctx, intentId)
					return false, err
				}

				return true, nil
			},
			onTreeSigningStarted: func(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error) {
				myPubkey := signerSession.GetPublicKey()
				if !slices.Contains(event.CosignersPubkeys, myPubkey) {
					return true, nil
				}

				commitmentTx, err := psbt.NewFromRawBytes(
					strings.NewReader(event.UnsignedCommitmentTx),
					true,
				)
				if err != nil {
					return false, err
				}

				batchOutput := commitmentTx.UnsignedTx.TxOut[0]
				batchOutputAmount := batchOutput.Value

				// use a fake sweep to create invalid signatures
				fakeSweepTapHash := sha256.Sum256([]byte("random_sweep_tap_hash"))

				if err := signerSession.Init(fakeSweepTapHash[:], batchOutputAmount, vtxoTree); err != nil {
					return false, err
				}

				nonces, err := signerSession.GetNonces()
				if err != nil {
					return false, err
				}

				if err = grpcAlice.SubmitTreeNonces(ctx, event.Id, signerSession.GetPublicKey(), nonces); err != nil {
					return false, err
				}

				return false, nil
			},
			onTreeNoncesAggregated: func(ctx context.Context, event client.TreeNoncesAggregatedEvent) (bool, error) {
				signerSession.SetAggregatedNonces(event.Nonces)

				sigs, err := signerSession.Sign()
				if err != nil {
					return false, err
				}

				err = grpcAlice.SubmitTreeSignatures(
					ctx,
					event.Id,
					signerSession.GetPublicKey(),
					sigs,
				)
				return err == nil, err
			},
		}

		_, err = arksdk.JoinBatchSession(t.Context(), stream, handlers)
		require.Error(t, err)

		// next settle should fail because the signature was invalid
		_, err = alice.Settle(t.Context())
		require.Error(t, err)

		// send should fail
		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			Amount: aliceVtxo.Amount,
			To:     aliceAddr,
		}})
		require.Error(t, err)
	})

	t.Run("failed to submit forfeit txs signatures", func(t *testing.T) {
		alice, grpcAlice := setupArkSDKWithTransport(t)
		defer alice.Stop()
		defer grpcAlice.Close()

		// faucet the alice's wallet
		_, aliceAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)
		faucetOffchain(t, alice, 0.001)
		require.NoError(t, err)

		vtxos, _, err := alice.ListVtxos(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		aliceVtxo := vtxos[0]

		// setup a random musig2 tree signer
		secKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		signerSession := tree.NewTreeSignerSession(secKey)

		intentId, err := alice.RegisterIntent(
			t.Context(),
			[]types.Vtxo{aliceVtxo},
			[]types.Utxo{},
			nil,
			[]types.Receiver{
				{
					Amount: aliceVtxo.Amount,
					To:     aliceAddr,
				},
			},
			[]string{signerSession.GetPublicKey()},
		)
		require.NoError(t, err)

		topics := arksdk.GetEventStreamTopics(
			[]types.Outpoint{aliceVtxo.Outpoint}, []tree.SignerSession{signerSession},
		)
		stream, close, err := grpcAlice.GetEventStream(t.Context(), topics)
		require.NoError(t, err)
		defer close()

		var batchExpiry arklib.RelativeLocktime
		handlers := &customBatchEventsHandler{
			onBatchStarted: func(ctx context.Context, event client.BatchStartedEvent) (bool, error) {
				buf := sha256.Sum256([]byte(intentId))
				hashedIntentId := hex.EncodeToString(buf[:])

				if slices.Contains(event.HashedIntentIds, hashedIntentId) {
					err := grpcAlice.ConfirmRegistration(ctx, intentId)
					batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
					return false, err
				}

				return true, nil
			},
			onTreeSigningStarted: func(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error) {
				myPubkey := signerSession.GetPublicKey()
				if !slices.Contains(event.CosignersPubkeys, myPubkey) {
					return true, nil
				}

				signerPubKey := secKey.PubKey()

				sweepClosure := script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{signerPubKey},
					},
					Locktime: batchExpiry,
				}

				script, err := sweepClosure.Script()
				if err != nil {
					return false, err
				}

				commitmentTx, err := psbt.NewFromRawBytes(
					strings.NewReader(event.UnsignedCommitmentTx),
					true,
				)
				if err != nil {
					return false, err
				}

				batchOutput := commitmentTx.UnsignedTx.TxOut[0]
				batchOutputAmount := batchOutput.Value

				sweepTapLeaf := txscript.NewBaseTapLeaf(script)
				sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
				root := sweepTapTree.RootNode.TapHash()

				if err := signerSession.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
					return false, err
				}

				nonces, err := signerSession.GetNonces()
				if err != nil {
					return false, err
				}

				if err = grpcAlice.SubmitTreeNonces(ctx, event.Id, signerSession.GetPublicKey(), nonces); err != nil {
					return false, err
				}

				return false, nil
			},
			onTreeNoncesAggregated: func(ctx context.Context, event client.TreeNoncesAggregatedEvent) (bool, error) {
				signerSession.SetAggregatedNonces(event.Nonces)

				sigs, err := signerSession.Sign()
				if err != nil {
					return false, err
				}

				err = grpcAlice.SubmitTreeSignatures(
					ctx,
					event.Id,
					signerSession.GetPublicKey(),
					sigs,
				)
				return err == nil, err
			},
			onBatchFinalization: func(ctx context.Context, event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree) error {
				return nil // do not submit forfeit txs
			},
		}

		_, err = arksdk.JoinBatchSession(t.Context(), stream, handlers)
		require.Error(t, err)

		// next settle should fail because the forfeit txs have not been submitted
		_, err = alice.Settle(t.Context())
		require.Error(t, err)

		// send should fail
		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			Amount: aliceVtxo.Amount,
			To:     aliceAddr,
		}})
		require.Error(t, err)
	})

	t.Run("failed to submit valid forfeit txs signatures", func(t *testing.T) {
		alice, grpcAlice := setupArkSDKWithTransport(t)
		defer alice.Stop()
		defer grpcAlice.Close()

		// faucet the alice's wallet
		_, aliceAddr, _, err := alice.Receive(t.Context())
		require.NoError(t, err)
		faucetOffchain(t, alice, 0.001)
		require.NoError(t, err)

		vtxos, _, err := alice.ListVtxos(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		aliceVtxo := vtxos[0]

		// setup a random musig2 tree signer
		secKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		signerSession := tree.NewTreeSignerSession(secKey)

		intentId, err := alice.RegisterIntent(
			t.Context(),
			[]types.Vtxo{aliceVtxo},
			[]types.Utxo{},
			nil,
			[]types.Receiver{
				{
					Amount: aliceVtxo.Amount,
					To:     aliceAddr,
				},
			},
			[]string{signerSession.GetPublicKey()},
		)
		require.NoError(t, err)

		topics := arksdk.GetEventStreamTopics(
			[]types.Outpoint{aliceVtxo.Outpoint}, []tree.SignerSession{signerSession},
		)
		stream, close, err := grpcAlice.GetEventStream(t.Context(), topics)
		require.NoError(t, err)
		defer close()

		info, err := grpcAlice.GetInfo(t.Context())
		require.NoError(t, err)
		var batchExpiry arklib.RelativeLocktime

		handlers := &customBatchEventsHandler{
			onBatchStarted: func(ctx context.Context, event client.BatchStartedEvent) (bool, error) {
				buf := sha256.Sum256([]byte(intentId))
				hashedIntentId := hex.EncodeToString(buf[:])

				if slices.Contains(event.HashedIntentIds, hashedIntentId) {
					err := grpcAlice.ConfirmRegistration(ctx, intentId)
					batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
					return false, err
				}

				return true, nil
			},
			onTreeSigningStarted: func(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error) {
				myPubkey := signerSession.GetPublicKey()
				if !slices.Contains(event.CosignersPubkeys, myPubkey) {
					return true, nil
				}

				signerPubKey := secKey.PubKey()

				sweepClosure := script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{signerPubKey},
					},
					Locktime: batchExpiry,
				}

				script, err := sweepClosure.Script()
				if err != nil {
					return false, err
				}

				commitmentTx, err := psbt.NewFromRawBytes(
					strings.NewReader(event.UnsignedCommitmentTx),
					true,
				)
				if err != nil {
					return false, err
				}

				batchOutput := commitmentTx.UnsignedTx.TxOut[0]
				batchOutputAmount := batchOutput.Value

				sweepTapLeaf := txscript.NewBaseTapLeaf(script)
				sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
				root := sweepTapTree.RootNode.TapHash()

				if err := signerSession.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
					return false, err
				}

				nonces, err := signerSession.GetNonces()
				if err != nil {
					return false, err
				}

				if err = grpcAlice.SubmitTreeNonces(ctx, event.Id, signerSession.GetPublicKey(), nonces); err != nil {
					return false, err
				}

				return false, nil
			},
			onTreeNoncesAggregated: func(ctx context.Context, event client.TreeNoncesAggregatedEvent) (bool, error) {
				signerSession.SetAggregatedNonces(event.Nonces)

				sigs, err := signerSession.Sign()
				if err != nil {
					return false, err
				}

				err = grpcAlice.SubmitTreeSignatures(
					ctx,
					event.Id,
					signerSession.GetPublicKey(),
					sigs,
				)
				return err == nil, err
			},
			onBatchFinalization: func(ctx context.Context, event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree) error {
				txhash, err := chainhash.NewHashFromStr(aliceVtxo.Txid)
				if err != nil {
					return err
				}

				// use a wrong script to create invalid signatures
				fakeScript := []byte("random_script")

				forfeitOutputAddr, err := btcutil.DecodeAddress(info.ForfeitAddress, nil)
				if err != nil {
					return err
				}

				forfeitOutputScript, err := txscript.PayToAddrScript(forfeitOutputAddr)
				if err != nil {
					return err
				}

				forfeitPtx, err := tree.BuildForfeitTx(
					[]*wire.OutPoint{{
						Hash:  *txhash,
						Index: aliceVtxo.VOut,
					}},
					[]uint32{wire.MaxTxInSequenceNum},
					[]*wire.TxOut{{Value: int64(aliceVtxo.Amount), PkScript: fakeScript}},
					forfeitOutputScript,
					0,
				)
				if err != nil {
					return err
				}

				encodedForfeitTx, err := forfeitPtx.B64Encode()
				if err != nil {
					return err
				}

				// sign the forfeit tx
				signedForfeitTx, err := alice.SignTransaction(
					context.Background(),
					encodedForfeitTx,
				)
				if err != nil {
					return err
				}

				return grpcAlice.SubmitSignedForfeitTxs(
					ctx, []string{signedForfeitTx}, "",
				)
			},
		}

		_, err = arksdk.JoinBatchSession(t.Context(), stream, handlers)
		require.Error(t, err)

		// next settle should fail because the forfeit txs have not been submitted
		_, err = alice.Settle(t.Context())
		require.Error(t, err)

		// send should fail
		_, err = alice.SendOffChain(t.Context(), []types.Receiver{{
			Amount: aliceVtxo.Amount,
			To:     aliceAddr,
		}})
		require.Error(t, err)
	})

	t.Run("failed to submit boarding inputs signatures", func(t *testing.T) {
		alice, wallet, _, grpcAlice := setupArkSDKwithPublicKey(t)
		defer alice.Stop()
		defer grpcAlice.Close()

		// faucet the alice's wallet
		_, offchainAddr, boardingAddr, err := wallet.NewAddress(t.Context(), false)
		require.NoError(t, err)

		faucetOnchain(t, boardingAddr.Address, 0.001)
		time.Sleep(5 * time.Second)

		info, err := grpcAlice.GetInfo(t.Context())
		require.NoError(t, err)

		explr, err := mempool_explorer.NewExplorer(
			"http://localhost:3000", arklib.BitcoinRegTest,
			mempool_explorer.WithPollInterval(time.Second),
		)
		require.NoError(t, err)
		boardingUtxos, err := explr.GetUtxos(boardingAddr.Address)
		require.NoError(t, err)
		require.NotEmpty(t, boardingUtxos)

		aliceUtxo := boardingUtxos[0]
		utxo := aliceUtxo.ToUtxo(
			arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: uint32(info.BoardingExitDelay),
			},
			boardingAddr.Tapscripts,
		)

		// setup a random musig2 tree signer
		secKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		signerSession := tree.NewTreeSignerSession(secKey)

		intentId, err := alice.RegisterIntent(
			t.Context(),
			[]types.Vtxo{},
			[]types.Utxo{utxo},
			nil,
			[]types.Receiver{
				{
					Amount: aliceUtxo.Amount,
					To:     offchainAddr.Address,
				},
			},
			[]string{signerSession.GetPublicKey()},
		)
		require.NoError(t, err)

		topics := arksdk.GetEventStreamTopics(
			[]types.Outpoint{utxo.Outpoint}, []tree.SignerSession{signerSession},
		)
		stream, close, err := grpcAlice.GetEventStream(t.Context(), topics)
		require.NoError(t, err)
		defer close()

		var batchExpiry arklib.RelativeLocktime
		handlers := &customBatchEventsHandler{
			onBatchStarted: func(ctx context.Context, event client.BatchStartedEvent) (bool, error) {
				buf := sha256.Sum256([]byte(intentId))
				hashedIntentId := hex.EncodeToString(buf[:])

				if slices.Contains(event.HashedIntentIds, hashedIntentId) {
					err := grpcAlice.ConfirmRegistration(ctx, intentId)
					batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
					return false, err
				}

				return true, nil
			},
			onTreeSigningStarted: func(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error) {
				myPubkey := signerSession.GetPublicKey()
				if !slices.Contains(event.CosignersPubkeys, myPubkey) {
					return true, nil
				}

				signerPubKey := secKey.PubKey()

				sweepClosure := script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{signerPubKey},
					},
					Locktime: batchExpiry,
				}

				script, err := sweepClosure.Script()
				if err != nil {
					return false, err
				}

				commitmentTx, err := psbt.NewFromRawBytes(
					strings.NewReader(event.UnsignedCommitmentTx),
					true,
				)
				if err != nil {
					return false, err
				}

				batchOutput := commitmentTx.UnsignedTx.TxOut[0]
				batchOutputAmount := batchOutput.Value

				sweepTapLeaf := txscript.NewBaseTapLeaf(script)
				sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
				root := sweepTapTree.RootNode.TapHash()

				if err := signerSession.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
					return false, err
				}

				nonces, err := signerSession.GetNonces()
				if err != nil {
					return false, err
				}

				if err = grpcAlice.SubmitTreeNonces(ctx, event.Id, signerSession.GetPublicKey(), nonces); err != nil {
					return false, err
				}

				return false, nil
			},
			onTreeNoncesAggregated: func(ctx context.Context, event client.TreeNoncesAggregatedEvent) (bool, error) {
				signerSession.SetAggregatedNonces(event.Nonces)

				sigs, err := signerSession.Sign()
				if err != nil {
					return false, err
				}

				err = grpcAlice.SubmitTreeSignatures(
					ctx,
					event.Id,
					signerSession.GetPublicKey(),
					sigs,
				)
				return err == nil, err
			},
			onBatchFinalization: func(ctx context.Context, event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree) error {
				commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
				if err != nil {
					return err
				}

				// modify the prevout amount to create invalid signature
				commitmentPtx.Inputs[0].WitnessUtxo.Value = int64(aliceUtxo.Amount + 2000)

				encodedCommitmentTx, err := commitmentPtx.B64Encode()
				if err != nil {
					return err
				}

				// sign the forfeit tx
				signedCommitmentTx, err := alice.SignTransaction(
					context.Background(),
					encodedCommitmentTx,
				)
				if err != nil {
					return err
				}

				return grpcAlice.SubmitSignedForfeitTxs(
					ctx, []string{}, signedCommitmentTx,
				)
			},
		}

		_, err = arksdk.JoinBatchSession(t.Context(), stream, handlers)
		require.Error(t, err)

		// next settle should fail because the forfeit txs have not been submitted
		_, err = alice.Settle(t.Context())
		require.Error(t, err)
	})
}

// TestFee tests the fee calculation for the onboarding and settlement of the funds.
// It first updates the 4 fee programs for intents.
func TestFee(t *testing.T) {
	originalFees, err := getIntentFees()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, clearIntentFees())
		if !isEmptyIntentFees(*originalFees) {
			require.NoError(t, updateIntentFees(*originalFees))
		}

		// verify the fees have been restored
		restoredFees, err := getIntentFees()
		require.NoError(t, err)
		require.Equal(t, originalFees, restoredFees)
	})

	fees := intentFees{
		// for input: free in case of recoverable or note, 1% of the amount otherwise
		// for output: 200 satoshis for onchain output, 0 for vtxo output
		IntentOffchainInputFeeProgram:  "inputType == 'note' || inputType == 'recoverable' ? 0.0 : amount*0.01",
		IntentOnchainInputFeeProgram:   "0.01 * amount",
		IntentOffchainOutputFeeProgram: "0.0",
		IntentOnchainOutputFeeProgram:  "200.0",
	}

	err = updateIntentFees(fees)
	require.NoError(t, err)

	ctx := t.Context()
	alice := setupArkSDK(t)
	bob := setupArkSDK(t)

	_, aliceOffchainAddr, aliceBoardingAddr, err := alice.Receive(ctx)
	require.NoError(t, err)
	_, bobOffchainAddr, bobBoardingAddr, err := bob.Receive(ctx)
	require.NoError(t, err)

	// Faucet Alice and Bob boarding addresses
	faucetOnchain(t, aliceBoardingAddr, 0.00021)
	faucetOnchain(t, bobBoardingAddr, 0.00021)
	time.Sleep(6 * time.Second)

	aliceBalance, err := alice.Balance(t.Context())
	require.NoError(t, err)
	require.NotNil(t, aliceBalance)
	require.Zero(t, int(aliceBalance.OffchainBalance.Total))
	require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
	require.NotEmpty(t, aliceBalance.OnchainBalance.LockedAmount)
	require.NotZero(t, int(aliceBalance.OnchainBalance.LockedAmount[0].Amount))

	bobBalance, err := bob.Balance(t.Context())
	require.NoError(t, err)
	require.NotNil(t, bobBalance)
	require.Zero(t, int(bobBalance.OffchainBalance.Total))
	require.Empty(t, int(bobBalance.OnchainBalance.SpendableAmount))
	require.NotEmpty(t, bobBalance.OnchainBalance.LockedAmount)
	require.NotZero(t, int(bobBalance.OnchainBalance.LockedAmount[0].Amount))

	wg := &sync.WaitGroup{}
	wg.Add(4)

	// They join the same batch to settle their funds
	var aliceIncomingErr, bobIncomingErr error
	var aliceIncomingFunds, bobIncomingFunds []types.Vtxo
	go func() {
		aliceIncomingFunds, aliceIncomingErr = alice.NotifyIncomingFunds(ctx, aliceOffchainAddr)
		wg.Done()
	}()
	go func() {
		bobIncomingFunds, bobIncomingErr = bob.NotifyIncomingFunds(ctx, bobOffchainAddr)
		wg.Done()
	}()

	var aliceCommitmentTx, bobCommitmentTx string
	var aliceBatchErr, bobBatchErr error
	go func() {
		aliceCommitmentTx, aliceBatchErr = alice.Settle(ctx)
		wg.Done()
	}()
	go func() {
		bobCommitmentTx, bobBatchErr = bob.Settle(ctx)
		wg.Done()
	}()

	wg.Wait()

	require.NoError(t, aliceIncomingErr)
	require.NotEmpty(t, aliceIncomingFunds)
	require.Len(t, aliceIncomingFunds, 1)
	require.NoError(t, bobIncomingErr)
	require.NotEmpty(t, bobIncomingFunds)
	require.Len(t, bobIncomingFunds, 1)
	require.NoError(t, aliceBatchErr)
	require.NoError(t, bobBatchErr)
	require.NotEmpty(t, aliceCommitmentTx)
	require.NotEmpty(t, bobCommitmentTx)
	require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

	aliceFirstVtxo := aliceIncomingFunds[0]
	bobFirstVtxo := bobIncomingFunds[0]

	// 21000 - 1% of 21000 = 20790
	require.Equal(t, 20790, int(aliceFirstVtxo.Amount))
	require.Equal(t, 20790, int(bobFirstVtxo.Amount))

	time.Sleep(time.Second)

	aliceBalance, err = alice.Balance(t.Context())
	require.NoError(t, err)
	require.NotNil(t, aliceBalance)
	require.NotZero(t, int(aliceBalance.OffchainBalance.Total))

	bobBalance, err = bob.Balance(t.Context())
	require.NoError(t, err)
	require.NotNil(t, bobBalance)
	require.NotZero(t, int(bobBalance.OffchainBalance.Total))

	time.Sleep(5 * time.Second)

	// Alice and Bob refresh their VTXOs by joining another batch together
	wg.Add(4)

	go func() {
		aliceIncomingFunds, aliceIncomingErr = alice.NotifyIncomingFunds(ctx, aliceOffchainAddr)
		wg.Done()
	}()
	go func() {
		bobIncomingFunds, bobIncomingErr = bob.NotifyIncomingFunds(ctx, bobOffchainAddr)
		wg.Done()
	}()

	go func() {
		aliceCommitmentTx, aliceBatchErr = alice.Settle(ctx)
		wg.Done()
	}()
	go func() {
		bobCommitmentTx, bobBatchErr = bob.Settle(ctx)
		wg.Done()
	}()

	wg.Wait()
	time.Sleep(time.Second)

	require.NoError(t, aliceIncomingErr)
	require.NoError(t, bobIncomingErr)
	require.NotEmpty(t, aliceIncomingFunds)
	require.Len(t, aliceIncomingFunds, 1)
	require.NotEmpty(t, bobIncomingFunds)
	require.Len(t, bobIncomingFunds, 1)
	require.NoError(t, aliceBatchErr)
	require.NoError(t, bobBatchErr)

	aliceSecondVtxo := aliceIncomingFunds[0]
	bobSecondVtxo := bobIncomingFunds[0]

	// 20790 - 1% of 20790 = 20582
	require.Equal(t, 20582, int(aliceSecondVtxo.Amount))
	require.Equal(t, 20582, int(bobSecondVtxo.Amount))

	require.NotEmpty(t, aliceCommitmentTx)
	require.NotEmpty(t, bobCommitmentTx)
	require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

	aliceBalance, err = alice.Balance(t.Context())
	require.NoError(t, err)
	require.NotNil(t, aliceBalance)
	require.NotZero(t, int(aliceBalance.OffchainBalance.Total))
	require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
	require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

	bobBalance, err = bob.Balance(t.Context())
	require.NoError(t, err)
	require.NotNil(t, bobBalance)
	require.NotZero(t, int(bobBalance.OffchainBalance.Total))
	require.Zero(t, int(bobBalance.OnchainBalance.SpendableAmount))
	require.Empty(t, bobBalance.OnchainBalance.LockedAmount)
}

func TestCollectedFees(t *testing.T) {
	// Record timestamp before rounds so we can query fees in this window.
	startTime := time.Now().Unix()

	// Configure 1% input fees so rounds generate non-zero collected fees.
	originalFees, err := getIntentFees()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, clearIntentFees())
		if !isEmptyIntentFees(*originalFees) {
			require.NoError(t, updateIntentFees(*originalFees))
		}
	})

	fees := intentFees{
		IntentOffchainInputFeeProgram:  "0.01 * amount",
		IntentOnchainInputFeeProgram:   "0.01 * amount",
		IntentOffchainOutputFeeProgram: "0.0",
		IntentOnchainOutputFeeProgram:  "0.0",
	}
	err = updateIntentFees(fees)
	require.NoError(t, err)

	ctx := t.Context()
	alice := setupArkSDK(t)

	_, aliceOffchainAddr, aliceBoardingAddr, err := alice.Receive(ctx)
	require.NoError(t, err)

	// Fund Alice and settle a round.
	faucetOnchain(t, aliceBoardingAddr, 0.001)
	time.Sleep(6 * time.Second)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	var incomingErr error
	go func() {
		_, incomingErr = alice.NotifyIncomingFunds(ctx, aliceOffchainAddr)
		wg.Done()
	}()

	var settleErr error
	go func() {
		_, settleErr = alice.Settle(ctx)
		wg.Done()
	}()

	wg.Wait()
	require.NoError(t, incomingErr)
	require.NoError(t, settleErr)

	time.Sleep(time.Second)

	// Query collected fees for the window that includes our round.
	endTime := time.Now().Unix() + 10
	collectedFees, err := getCollectedFees(startTime-1, endTime)
	require.NoError(t, err)
	require.NotZero(t, collectedFees, "expected non-zero collected fees after a round with 1%% input fees")

	// Query with a future window — should return zero.
	futureFees, err := getCollectedFees(endTime, 0)
	require.NoError(t, err)
	require.Zero(t, futureFees, "expected zero collected fees for future time range")
}

func TestAsset(t *testing.T) {
	// This test ensures that an asset vtxo can be issued, transfered and then refreshed
	t.Run("transfer and renew", func(t *testing.T) {
		ctx := t.Context()
		const supply = 5_000
		const transferAmount = 1_200

		alice := setupArkSDK(t)
		bob := setupArkSDK(t)

		wg := &sync.WaitGroup{}
		wg.Go(func() {
			faucetOffchain(t, alice, 0.002)
		})
		wg.Go(func() {
			faucetOffchain(t, bob, 0.001)
		})
		wg.Wait()

		txid, assetIds, err := alice.IssueAsset(ctx, supply, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)
		assetId := assetIds[0].String()

		time.Sleep(3 * time.Second)

		assetVtxos := listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 1)
		require.Len(t, assetVtxos[0].Assets, 1)
		requireVtxoHasAsset(t, assetVtxos[0], assetId, uint64(supply))
		require.Equal(t, txid, assetVtxos[0].Txid)

		_, bobAddr, _, err := bob.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobAddr)

		_, err = alice.SendOffChain(
			ctx, []types.Receiver{
				{To: bobAddr, Amount: 400, Assets: []types.Asset{
					{AssetId: assetId, Amount: transferAmount},
				}},
			},
		)
		require.NoError(t, err)

		// Allow some time for bob to receive the vtxo from indexer
		time.Sleep(3 * time.Second)

		receiverAssetVtxos := listVtxosWithAsset(t, bob, assetId)
		require.Len(t, receiverAssetVtxos, 1)
		require.Len(t, receiverAssetVtxos[0].Assets, 1)
		requireVtxoHasAsset(t, receiverAssetVtxos[0], assetId, uint64(transferAmount))

		bobBalance, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.NotNil(t, bobBalance.AssetBalances)

		assetBalance, ok := bobBalance.AssetBalances[assetId]
		require.True(t, ok)
		require.Equal(t, int(assetBalance), int(transferAmount))

		var aliceErr, bobErr error
		wg = &sync.WaitGroup{}
		wg.Go(func() {
			_, aliceErr = alice.Settle(ctx)
		})
		wg.Go(func() {
			_, bobErr = bob.Settle(ctx)
		})

		wg.Wait()
		require.NoError(t, aliceErr)
		require.NoError(t, bobErr)

		bobBalanceAfterRenew, err := bob.Balance(ctx)
		require.NoError(t, err)

		assetBalanceAfterRenew, ok := bobBalanceAfterRenew.AssetBalances[assetId]
		require.True(t, ok)
		require.Equal(t, int(assetBalanceAfterRenew), int(transferAmount))

		require.Equal(t, int(assetBalance), int(assetBalanceAfterRenew))
	})

	// These tests ensure many type of issuances can done offchain
	t.Run("issuance", func(t *testing.T) {
		t.Run("without control asset", func(t *testing.T) {
			ctx := t.Context()
			alice := setupArkSDK(t)
			faucetOffchain(t, alice, 0.01)

			_, assetIds, err := alice.IssueAsset(ctx, 1, nil, nil)
			require.NoError(t, err)
			require.Len(t, assetIds, 1)
		})

		t.Run("with new control asset", func(t *testing.T) {
			ctx := t.Context()
			alice := setupArkSDK(t)
			faucetOffchain(t, alice, 0.01)

			_, assetIds, err := alice.IssueAsset(ctx, 1, types.NewControlAsset{Amount: 1}, nil)
			require.NoError(t, err)
			require.Len(t, assetIds, 2)

			controlAssetId := assetIds[0].String()
			assetId := assetIds[1].String()
			require.NotEqual(t, controlAssetId, assetId)
		})

		t.Run("with existing control asset", func(t *testing.T) {
			ctx := t.Context()
			alice := setupArkSDK(t)
			faucetOffchain(t, alice, 0.01)

			// issue control asset
			_, assetIds, err := alice.IssueAsset(ctx, 1, nil, nil)
			require.NoError(t, err)
			require.Len(t, assetIds, 1)
			controlAssetId := assetIds[0].String()

			time.Sleep(3 * time.Second)

			// issue another asset	 with existing control asset
			_, assetIds2, err := alice.IssueAsset(
				ctx,
				1,
				types.ExistingControlAsset{ID: controlAssetId},
				nil,
			)
			require.NoError(t, err)
			require.Len(t, assetIds2, 1)

			require.NotEqual(t, assetIds[0].String(), assetIds2[0].String())
		})
	})

	// This test ensures that an already issued asset can be reissued with the usage of its
	// control asset
	t.Run("reissuance", func(t *testing.T) {
		ctx := t.Context()

		alice := setupArkSDK(t)
		faucetOffchain(t, alice, 0.01)

		// issue an asset with a control asset
		_, assetIds, err := alice.IssueAsset(ctx, 1, types.NewControlAsset{Amount: 1}, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 2)

		controlAssetId := assetIds[0].String()
		assetId := assetIds[1].String()
		require.NotEqual(t, controlAssetId, assetId)

		time.Sleep(3 * time.Second)

		controlVtxos := listVtxosWithAsset(t, alice, controlAssetId)
		require.Len(t, controlVtxos, 1)
		require.Len(
			t,
			controlVtxos[0].Assets,
			2,
		) // should hold both the control asset and the issued asset
		requireVtxoHasAsset(t, controlVtxos[0], controlAssetId, 1)
		requireVtxoHasAsset(t, controlVtxos[0], assetId, 1)

		_, err = alice.ReissueAsset(ctx, assetId, 1000)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		assetVtxos := listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 2)
	})

	// This test ensures that an asset can be burned for any given amount
	t.Run("burn", func(t *testing.T) {
		ctx := t.Context()

		alice := setupArkSDK(t)
		faucetOffchain(t, alice, 0.01)

		_, assetIds, err := alice.IssueAsset(ctx, 5000, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)
		assetId := assetIds[0].String()

		time.Sleep(2 * time.Second)

		assetVtxos := listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 1)
		require.Len(t, assetVtxos[0].Assets, 1)
		requireVtxoHasAsset(t, assetVtxos[0], assetId, 5000)

		_, err = alice.BurnAsset(ctx, assetId, 1500)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		assetVtxos = listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 1)
		require.Len(t, assetVtxos[0].Assets, 1)
		requireVtxoHasAsset(t, assetVtxos[0], assetId, 3500)
	})

	// This test ensures that Alice can unroll her asset vtxos onchain
	t.Run("unroll", func(t *testing.T) {
		ctx := t.Context()
		alice := setupArkSDK(t)

		// Fund the client with the exact amount needed for an issuance to not create any change
		faucetOffchain(t, alice, 0.00000330)

		supply := uint64(6_000)
		txid, assetIds, err := alice.IssueAsset(ctx, supply, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)
		assetId := assetIds[0].String()

		time.Sleep(3 * time.Second)

		assetVtxos, spentVtxos, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spentVtxos, 1)
		require.Len(t, assetVtxos, 1)
		require.Len(t, assetVtxos[0].Assets, 1)
		requireVtxoHasAsset(t, assetVtxos[0], assetId, supply)
		require.Equal(t, txid, assetVtxos[0].Txid)

		// Fund alice's onchain address to cover network fees for the unroll
		onchainAddr, _, _, err := alice.Receive(ctx)
		require.NoError(t, err)

		faucetOnchain(t, onchainAddr, 0.01)
		time.Sleep(5 * time.Second)

		err = alice.Unroll(ctx)
		require.NoError(t, err)

		// Generate a block to confirm the leaf tx just unrolled and make the server react by
		// broadcasting the checkpoint tx that spent the vtxo offchain
		err = generateBlocks(1)
		require.NoError(t, err)
		time.Sleep(5 * time.Second)
		// Generate another block to confirm the checkpoint tx so that alice can unroll her asset
		// vtxo
		err = generateBlocks(1)
		require.NoError(t, err)
		time.Sleep(5 * time.Second)

		// Finish the unroll and broadcast the ark issuance tx
		err = alice.Unroll(ctx)
		require.NoError(t, err)

		// Generate a block to confirm the issuance tx onchain
		err = generateBlocks(1)
		require.NoError(t, err)

		time.Sleep(8 * time.Second)

		// alice vtxos should have been unrolled
		spendableVtxos, spentVtxos, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.Empty(t, spendableVtxos)
		require.Len(t, spentVtxos, 2)
		require.True(t, spentVtxos[0].Unrolled)

		aliceBalance, err := alice.Balance(ctx)
		require.NoError(t, err)

		_, ok := aliceBalance.AssetBalances[assetId]
		require.False(t, ok)
	})
}

// TestTxListenerChurn verifies that the gRPC transaction stream fanout is
// resilient to subscription churn. It runs three concurrent activities:
//
//  1. A "sentinel" stream that stays open for the full test duration and counts
//     every tx event it receives. If the server panics or the fanout breaks, the
//     sentinel's gRPC connection will error out and the assertions at the end
//     will catch it.
//  2. N churn workers that each open a tx stream, optionally read one event,
//     then immediately close the stream — repeating as fast as possible. This
//     simulates a DoS-style load on the subscribe/unsubscribe path.
//  3. A tx producer that periodically sends offchain payments so there is a
//     steady flow of events for the sentinel to observe.
//
// The test passes when the sentinel stream observes at least one event and
// reports no errors, proving the fanout survived the churn.
func TestTxListenerChurn(t *testing.T) {
	const (
		testDuration           = 30 * time.Second
		churnWorkers           = 8
		txProducerDelay        = 200 * time.Millisecond
		minimumTxEvents        = 1
		sendAmount      uint64 = 1000
	)

	ctx := t.Context()

	// Bootstrap sender/receiver clients and fund sender for repeated tx production.
	sender := setupArkSDK(t)
	receiver := setupArkSDK(t)
	alice, transport := setupArkSDKWithTransport(t)
	defer alice.Stop()
	defer transport.Close()

	faucetOffchain(t, sender, 0.01)

	stressCtx, cancel := context.WithTimeout(ctx, testDuration)
	defer cancel()

	var sentinelTxEvents atomic.Int64
	var sentinelErrors atomic.Int64
	var producedTxEvents atomic.Int64
	var retryableSubscribeErrors atomic.Int64
	sentinelDone := make(chan struct{})
	errCh := make(chan error, churnWorkers+8)

	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	// The sentinel stream stays open for the full stress window and counts
	// tx events. Under heavy churn (especially in CI) the sentinel's own
	// connection can hit transient errors, so it reconnects rather than
	// giving up. A persistent failure (server crash) will prevent any
	// events from being observed, which the assertions below will catch.
	closeSentinelStream := func() {}
	go func() {
		defer close(sentinelDone)
		for {
			if stressCtx.Err() != nil {
				return
			}

			stream, closeStream, err := transport.GetTransactionsStream(stressCtx)
			if err != nil {
				if stressCtx.Err() != nil {
					return
				}
				sentinelErrors.Add(1)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			closeSentinelStream = closeStream

			for {
				select {
				case <-stressCtx.Done():
					return
				case ev, ok := <-stream:
					if !ok {
						goto reconnect
					}
					if ev.Err != nil {
						sentinelErrors.Add(1)
						goto reconnect
					}
					if ev.ArkTx != nil {
						sentinelTxEvents.Add(1)
					}
					if ev.CommitmentTx != nil {
						sentinelTxEvents.Add(1)
					}
				}
			}

		reconnect:
			closeStream()
			if stressCtx.Err() != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	var wg sync.WaitGroup

	// Launch churn workers. Each worker creates its own gRPC client, opens a
	// tx stream, waits up to 10ms, then tears it down — repeating for the
	// full stress window. This hammers the server's subscribe/unsubscribe
	// path with concurrent mutations to the listener map. Transient network
	// errors (port exhaustion, connection resets) are expected under this
	// load and are counted rather than treated as failures.
	wg.Add(churnWorkers)
	for i := range churnWorkers {
		go func(workerID int) {
			defer wg.Done()

			streamClient, err := grpcclient.NewClient(serverUrl, false)
			if err != nil {
				if stressCtx.Err() != nil {
					return
				}
				if isRetryableChurnError(err) {
					retryableSubscribeErrors.Add(1)
					time.Sleep(churnWorkerBackoff(workerID))
				} else {
					reportErr(fmt.Errorf("churn worker %d create client: %w", workerID, err))
					return
				}
			}
			defer func() {
				if streamClient != nil {
					streamClient.Close()
				}
			}()

			for {
				select {
				case <-stressCtx.Done():
					return
				default:
				}

				// Reconnect if the previous iteration tore down the client
				// due to a transient error.
				if streamClient == nil {
					streamClient, err = grpcclient.NewClient(serverUrl, false)
					if err != nil {
						if stressCtx.Err() != nil {
							return
						}
						if isRetryableChurnError(err) {
							retryableSubscribeErrors.Add(1)
							time.Sleep(churnWorkerBackoff(workerID))
							continue
						}
						reportErr(fmt.Errorf("churn worker %d create client: %w", workerID, err))
						return
					}
				}

				// Subscribe, optionally read one event, then immediately
				// close — this is the core churn action.
				churnStream, closeChurnStream, err := streamClient.GetTransactionsStream(stressCtx)
				if err != nil {
					if stressCtx.Err() != nil {
						return
					}
					if isRetryableChurnError(err) {
						retryableSubscribeErrors.Add(1)
						streamClient.Close()
						streamClient = nil
						time.Sleep(churnWorkerBackoff(workerID))
						continue
					}
					reportErr(fmt.Errorf("churn worker %d subscribe: %w", workerID, err))
					return
				}

				select {
				case <-stressCtx.Done():
				case <-time.After(10 * time.Millisecond):
				case <-churnStream:
				}

				closeChurnStream()
				time.Sleep(churnWorkerBackoff(workerID))
			}
		}(i)
	}

	// Produce a steady stream of offchain transactions while the churn
	// workers are running. Without real tx events flowing through the
	// fanout, the sentinel would have nothing to observe and the test
	// would be meaningless.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(txProducerDelay)
		defer ticker.Stop()

		for {
			select {
			case <-stressCtx.Done():
				return
			case <-ticker.C:
				_, receiverOffchainAddr, _, err := receiver.Receive(stressCtx)
				if err != nil {
					reportErr(fmt.Errorf("tx producer receive address: %w", err))
					return
				}

				txid, err := sender.SendOffChain(stressCtx, []types.Receiver{{
					To:     receiverOffchainAddr,
					Amount: sendAmount,
				}})
				if err != nil {
					if stressCtx.Err() != nil {
						return
					}
					reportErr(fmt.Errorf("tx producer send offchain: %w", err))
					return
				}
				if txid == "" {
					reportErr(fmt.Errorf("tx producer got empty txid"))
					return
				}
				producedTxEvents.Add(1)
			}
		}
	}()

	// Wait for the stress window to expire, then drain all goroutines and
	// close the sentinel stream.
	<-stressCtx.Done()
	wg.Wait()
	closeSentinelStream()
	<-sentinelDone

	// Drain the error channel — any non-retryable error from a churn
	// worker or the tx producer is a test failure.
	var firstRunErr error
	select {
	case runErr := <-errCh:
		firstRunErr = runErr
	default:
	}

	// The producer must have submitted events and the sentinel must have
	// observed them. Transient sentinel errors are tolerated (the sentinel
	// reconnects), but if the server truly crashed the sentinel would
	// never observe any events.
	require.GreaterOrEqual(
		t,
		producedTxEvents.Load(),
		int64(minimumTxEvents),
		"producer did not submit tx events during churn",
	)

	require.GreaterOrEqual(
		t,
		sentinelTxEvents.Load(),
		int64(minimumTxEvents),
		"sentinel subscription did not observe tx events during churn",
	)

	require.NoError(t, firstRunErr)

	for {
		select {
		case runErr := <-errCh:
			require.NoError(t, runErr)
		default:
			return
		}
	}
}

// TestEventListenerChurn is the event-stream counterpart of TestTxListenerChurn.
// Instead of offchain transactions, clients join batches to generate
// events. The structure mirrors the tx test:
//
//  1. A sentinel event stream stays open for the full duration and counts
//     batch-lifecycle events. A broken fanout will sever this stream.
//  2. N churn workers rapidly open/close event streams to stress the
//     subscribe/unsubscribe path.
//  3. A batch producer drives Settle+NotifyIncomingFunds across multiple
//     participants to generate a steady flow of events.
//
// The test passes when at least one batch completes, the sentinel observes
// events, and no sentinel errors are recorded.
func TestEventListenerChurn(t *testing.T) {
	const (
		testDuration      = 40 * time.Second
		churnWorkers      = 16
		participantsCount = 4
		producerLoopDelay = 250 * time.Millisecond
		roundTimeout      = 20 * time.Second
		minimumRounds     = 1
	)

	ctx := t.Context()

	// Set up multiple funded participants so that settlement rounds
	// produce real on-chain activity and event-stream events.
	sentinelClient, eventTransport := setupArkSDKWithTransport(t)
	defer sentinelClient.Stop()
	defer eventTransport.Close()

	participants := make([]arksdk.ArkClient, 0, participantsCount)
	offchainAddrs := make([]string, 0, participantsCount)

	participants = append(participants, sentinelClient)
	for i := 1; i < participantsCount; i++ {
		participants = append(participants, setupArkSDK(t))
	}

	for _, participant := range participants {
		_, offchainAddr, _, err := participant.Receive(ctx)
		require.NoError(t, err)
		offchainAddrs = append(offchainAddrs, offchainAddr)
		faucetOffchain(t, participant, 0.001)
	}

	stressCtx, cancel := context.WithTimeout(ctx, testDuration)
	defer cancel()

	var sentinelEvents atomic.Int64
	var sentinelErrors atomic.Int64
	var producedRounds atomic.Int64
	var retryableSubscribeErrors atomic.Int64
	sentinelDone := make(chan struct{})
	errCh := make(chan error, churnWorkers+8)

	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	// The sentinel stream stays open for the full stress window and counts
	// events. Under heavy churn (especially in CI) the sentinel's own
	// connection can hit transient errors, so it reconnects rather than
	// giving up. A persistent failure (server crash) will prevent any
	// events from being observed, which the assertions below will catch.
	closeSentinelStream := func() {} // replaced on each (re)connect
	go func() {
		defer close(sentinelDone)
		for {
			if stressCtx.Err() != nil {
				return
			}

			sentinelStream, closeStream, err := eventTransport.GetEventStream(stressCtx, nil)
			if err != nil {
				if stressCtx.Err() != nil {
					return
				}
				sentinelErrors.Add(1)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			closeSentinelStream = closeStream

			for {
				select {
				case <-stressCtx.Done():
					closeStream()
					return
				case ev, ok := <-sentinelStream:
					if !ok {
						goto reconnect
					}
					if ev.Err != nil {
						sentinelErrors.Add(1)
						goto reconnect
					}
					if ev.Event == nil {
						continue
					}
					sentinelEvents.Add(1)
				}
			}

		reconnect:
			closeStream()
			if stressCtx.Err() != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	var wg sync.WaitGroup

	// Launch churn workers against the event stream. Same pattern as
	// TestTxListenerChurn's churn workers but targeting GetEventStream
	// instead of GetTransactionsStream. Each worker uses a short-lived
	// context (3s) per subscription so the server sees a mix of client-
	// initiated closes and context deadline cancellations.
	wg.Add(churnWorkers)
	for i := range churnWorkers {
		go func(workerID int) {
			defer wg.Done()

			streamClient, err := grpcclient.NewClient(serverUrl, false)
			if err != nil {
				if stressCtx.Err() != nil {
					return
				}
				if isRetryableChurnError(err) {
					retryableSubscribeErrors.Add(1)
					time.Sleep(churnWorkerBackoff(workerID))
				} else {
					reportErr(fmt.Errorf("churn worker %d create client: %w", workerID, err))
					return
				}
			}
			defer func() {
				if streamClient != nil {
					streamClient.Close()
				}
			}()

			for {
				select {
				case <-stressCtx.Done():
					return
				default:
				}

				// Reconnect after a transient error tore down the client.
				if streamClient == nil {
					streamClient, err = grpcclient.NewClient(serverUrl, false)
					if err != nil {
						if stressCtx.Err() != nil {
							return
						}
						if isRetryableChurnError(err) {
							retryableSubscribeErrors.Add(1)
							time.Sleep(churnWorkerBackoff(workerID))
							continue
						}
						reportErr(fmt.Errorf("churn worker %d create client: %w", workerID, err))
						return
					}
				}

				// Subscribe with a short deadline, optionally read one
				// event, then tear down — the core churn action.
				churnCtx, cancelChurn := context.WithTimeout(stressCtx, 3*time.Second)
				churnStream, closeChurnStream, err := streamClient.GetEventStream(churnCtx, nil)
				if err != nil {
					cancelChurn()
					if stressCtx.Err() != nil {
						return
					}
					if isRetryableChurnError(err) {
						retryableSubscribeErrors.Add(1)
						streamClient.Close()
						streamClient = nil
						time.Sleep(churnWorkerBackoff(workerID))
						continue
					}
					reportErr(fmt.Errorf("churn worker %d subscribe: %w", workerID, err))
					return
				}

				select {
				case <-stressCtx.Done():
				case <-time.After(10 * time.Millisecond):
				case <-churnStream:
				}

				closeChurnStream()
				cancelChurn()
				time.Sleep(churnWorkerBackoff(workerID))
			}
		}(i)
	}

	// Drive settlement rounds in a loop. Each iteration asks all
	// participants to Settle and NotifyIncomingFunds concurrently. A round
	// is counted as successful only if every participant settles with the
	// same commitment txid. Failed rounds (timeouts, mismatched txids) are
	// silently skipped — we only need at least one to succeed to prove the
	// event stream delivered events under churn.
	runRoundProducer := func() {
		defer wg.Done()

		for {
			if stressCtx.Err() != nil {
				return
			}

			roundCtx, cancelRound := context.WithTimeout(stressCtx, roundTimeout)
			notifyErrors := make([]error, len(participants))
			settleErrors := make([]error, len(participants))
			commitmentTxids := make([]string, len(participants))

			// Kick off Settle + NotifyIncomingFunds for every participant
			// in parallel — this is what triggers event-stream events.
			roundWG := &sync.WaitGroup{}
			roundWG.Add(len(participants) * 2)
			for i := range participants {
				idx := i
				go func() {
					defer roundWG.Done()
					_, notifyErrors[idx] = participants[idx].NotifyIncomingFunds(
						roundCtx,
						offchainAddrs[idx],
					)
				}()
				go func() {
					defer roundWG.Done()
					commitmentTxids[idx], settleErrors[idx] = participants[idx].Settle(roundCtx)
				}()
			}

			roundDone := make(chan struct{})
			go func() {
				roundWG.Wait()
				close(roundDone)
			}()

			select {
			case <-roundDone:
			case <-stressCtx.Done():
				cancelRound()
				return
			case <-time.After(roundTimeout + 2*time.Second):
				cancelRound()
				continue
			}
			cancelRound()

			if stressCtx.Err() != nil {
				return
			}

			for _, notifyErr := range notifyErrors {
				if notifyErr != nil {
					continue
				}
			}

			// Validate the round: all participants must have settled with
			// the same commitment txid.
			var expectedCommitmentTxid string
			roundOK := true
			for i, settleErr := range settleErrors {
				if settleErr != nil {
					roundOK = false
					break
				}
				if commitmentTxids[i] == "" {
					roundOK = false
					break
				}
				if expectedCommitmentTxid == "" {
					expectedCommitmentTxid = commitmentTxids[i]
					continue
				}
				if commitmentTxids[i] != expectedCommitmentTxid {
					roundOK = false
					break
				}
			}

			if roundOK {
				producedRounds.Add(1)
			}

			select {
			case <-stressCtx.Done():
				return
			case <-time.After(producerLoopDelay):
			}
		}
	}
	wg.Add(1)
	go runRoundProducer()

	// Wait for the stress window to expire, then drain all goroutines and
	// close the sentinel stream.
	<-stressCtx.Done()
	closeSentinelStream()
	wg.Wait()
	select {
	case <-sentinelDone:
	case <-time.After(10 * time.Second):
		t.Log("sentinel goroutine did not exit within 10s")
	}

	// At least one round must have completed and the sentinel must have
	// observed events. Transient sentinel errors are tolerated (the
	// sentinel reconnects), but if the server truly crashed the sentinel
	// would never observe any events.
	require.GreaterOrEqual(
		t,
		producedRounds.Load(),
		int64(minimumRounds),
		"round producer did not complete rounds during churn",
	)

	require.Greater(
		t,
		sentinelEvents.Load(),
		int64(0),
		"sentinel event stream did not observe events during churn",
	)

	// Drain the error channel — any non-retryable error from a churn
	// worker is a test failure.
	for {
		select {
		case runErr := <-errCh:
			require.NoError(t, runErr)
		default:
			return
		}
	}
}
