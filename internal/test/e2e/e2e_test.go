package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	mempool_explorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/redemption"
	inmemorystoreconfig "github.com/arkade-os/go-sdk/store/inmemory"
	"github.com/arkade-os/go-sdk/types"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
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
	redeemAddress    = "bcrt1q2wrgf2hrkfegt0t97cnv4g5yvfjua9k6vua54d"
	onchainAddress   = "bcrt1q2wrgf2hrkfegt0t97cnv4g5yvfjua9k6vua54d"
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
		time.Sleep(5 * time.Second)

		aliceBalance, err := alice.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.Zero(t, int(aliceBalance.OffchainBalance.Total))
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.NotEmpty(t, aliceBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, int(aliceBalance.OnchainBalance.LockedAmount[0].Amount))

		bobBalance, err := bob.Balance(t.Context(), false)
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

		aliceBalance, err = alice.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.NotZero(t, int(aliceBalance.OffchainBalance.Total))

		bobBalance, err = bob.Balance(t.Context(), false)
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

		require.NoError(t, aliceIncomingErr)
		require.NoError(t, bobIncomingErr)
		require.NoError(t, aliceBatchErr)
		require.NoError(t, bobBatchErr)
		require.NotEmpty(t, aliceCommitmentTx)
		require.NotEmpty(t, bobCommitmentTx)
		require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

		aliceBalance, err = alice.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.NotZero(t, int(aliceBalance.OffchainBalance.Total))
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

		bobBalance, err = bob.Balance(t.Context(), false)
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

		balance, err := alice.Balance(t.Context(), false)
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

		balance, err = alice.Balance(t.Context(), false)
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

		balance, err := alice.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.NotZero(t, balance.OffchainBalance.Total)
		require.Empty(t, balance.OnchainBalance.LockedAmount)

		err = alice.Unroll(t.Context())
		require.NoError(t, err)

		err = generateBlocks(1)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		balance, err = alice.Balance(t.Context(), false)
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

		bobBalance, err := bob.Balance(t.Context(), false)
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
		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 21000,
		}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)

		bobBalance, err = bob.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.NotZero(t, bobBalance.OffchainBalance.Total)
		require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

		// Fund Bob's onchain wallet to cover network fees for the unroll
		faucetOnchain(t, bobOnchainAddr, 0.0001)
		time.Sleep(5 * time.Second)

		// Unroll the whole chain untill the checkpoint tx
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

		time.Sleep(5 * time.Second)

		// Bob now just needs to wait for the unilateral exit delay to spend the unrolled VTXOs
		bobBalance, err = bob.Balance(t.Context(), false)
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

			aliceBalance, err := alice.Balance(t.Context(), false)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)

			bobBalance, err := bob.Balance(t.Context(), false)
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

			bobOnchainAddr, _, _, err := bob.Receive(t.Context())
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			// Send to Bob's onchain address
			_, err = alice.CollaborativeExit(t.Context(), bobOnchainAddr, 21000, false)
			require.NoError(t, err)

			time.Sleep(5 * time.Second)

			prevTotalBalance := int(aliceBalance.OffchainBalance.Total)
			aliceBalance, err = alice.Balance(t.Context(), false)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)
			require.Less(t, int(aliceBalance.OffchainBalance.Total), prevTotalBalance)

			bobBalance, err = bob.Balance(t.Context(), false)
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

			aliceBalance, err := alice.Balance(t.Context(), false)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)
			require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

			bobBalance, err := bob.Balance(t.Context(), false)
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

			bobOnchainAddr, _, _, err := bob.Receive(t.Context())
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			// Send all to Bob's onchain address
			_, err = alice.CollaborativeExit(t.Context(), bobOnchainAddr, 21000, false)
			require.NoError(t, err)

			time.Sleep(5 * time.Second)

			aliceBalance, err = alice.Balance(t.Context(), false)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Zero(t, int(aliceBalance.OffchainBalance.Total))
			require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

			bobBalance, err = bob.Balance(t.Context(), false)
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

			faucetOnchain(t, aliceBoardingAddr, 0.001)
			time.Sleep(5 * time.Second)

			_, err = alice.CollaborativeExit(t.Context(), bobOnchainAddr, 21000, false)
			require.Error(t, err)

			require.ErrorContains(t, err, "include onchain inputs and outputs")
		})
	})
}

func TestReactToFraud(t *testing.T) {
	// In this test Alice refreshes a VTXO and tries to unroll the one just forfeited.
	// The server should react by broadcasting the forfeit tx and claiming the unrolled VTXO before
	// Alice's timelock expires
	t.Run("react to unroll of forfeited vtxos", func(t *testing.T) {
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

		// Give time to the explorer to track down the braodcasted txs.
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
		time.Sleep(5 * time.Second)

		// Ensure the unrolled vtxo is now spent. The server swept it by broadcasting the forfeit tx.
		spentStatus, err = expl.GetTxOutspends(vtxo.Txid)
		require.NoError(t, err)
		require.NotEmpty(t, spentStatus)
		require.True(t, spentStatus[vtxo.VOut].Spent)
		require.NotEmpty(t, spentStatus[vtxo.VOut].SpentBy)
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
				ctx, false, []types.Receiver{{To: offchainAddress, Amount: 1000}},
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

			// give time for the server to detect and process the fraud
			err = generateBlocks(30)
			require.NoError(t, err)

			balance, err := sdkClient.Balance(ctx, false)
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
				ctx, false, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
			)
			require.NoError(t, err)
			require.NotEmpty(t, txid)

			wg.Wait()

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
		go func() {
			defer wg.Done()
			vtxos, err := bob.NotifyIncomingFunds(ctx, bobAddress)
			require.NoError(t, err)
			require.NotNil(t, vtxos)
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 1000}})
		require.NoError(t, err)

		wg.Wait()

		bobVtxos, _, err := bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 1)

		wg.Add(1)
		go func() {
			defer wg.Done()
			vtxos, err := bob.NotifyIncomingFunds(ctx, bobAddress)
			require.NoError(t, err)
			require.NotNil(t, vtxos)
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 2)

		wg.Add(1)
		go func() {
			defer wg.Done()
			vtxos, err := bob.NotifyIncomingFunds(ctx, bobAddress)
			require.NoError(t, err)
			require.NotNil(t, vtxos)
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 3)

		wg.Add(1)
		go func() {
			defer wg.Done()
			vtxos, err := bob.NotifyIncomingFunds(ctx, bobAddress)
			require.NoError(t, err)
			require.NotNil(t, vtxos)
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()

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
			_, err := alice.SendOffChain(t.Context(), false, []types.Receiver{{
				To:     bobOffchainAddr,
				Amount: amount,
			}})
			require.NoError(t, err)
			wg.Wait()
			require.NoError(t, incomingErr)
		}

		wg.Add(1)
		var incomingErr error
		go func() {
			_, incomingErr = alice.NotifyIncomingFunds(t.Context(), aliceOffchainAddr)
			wg.Done()
		}()
		_, err = bob.SendOffChain(t.Context(), false, []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: numInputs * amount,
		}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)
	})

	// In this test Alice sends to Bob a sub-dust VTXO. Bob can't spend or settle his VTXO.
	// He must receive other offchain funds to be able to settle them into a non-sub-dust that
	// can be spent
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

		var incomingErr error
		go func() {
			_, incomingErr = bob.NotifyIncomingFunds(t.Context(), bobOffchainAddr)
			wg.Done()
		}()

		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 100, // Sub-dust amount
		}})
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)

		_, err = bob.SendOffChain(t.Context(), false, []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: 100,
		}})
		require.Error(t, err)

		_, err = bob.Settle(t.Context())
		require.Error(t, err)

		wg.Add(1)
		go func() {
			_, incomingErr = bob.NotifyIncomingFunds(t.Context(), bobOffchainAddr)
			wg.Done()
		}()

		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 300, // Another sub-dust amount
		}})
		require.NoError(t, err)

		wg.Wait()
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
		txid, err := alice.Settle(ctx, arksdk.WithRecoverableVtxos)
		require.NoError(t, err)

		wg.Wait()
		require.NoError(t, incomingErr)

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
		var vtxo types.Vtxo
		go func() {
			defer wg.Done()
			vtxos, err := alice.NotifyIncomingFunds(ctx, offchainAddr)
			require.NoError(t, err)
			require.NotEmpty(t, vtxos)
			require.Len(t, vtxos, 1)
			vtxo = vtxos[0]
		}()

		// settle the boarding utxo
		_, err = alice.Settle(ctx)
		require.NoError(t, err)

		wg.Wait()

		// self-send the VTXO to create a checkpoint output
		txid, err := alice.SendOffChain(
			ctx,
			false,
			[]types.Receiver{{To: offchainAddr, Amount: vtxo.Amount}},
		)
		require.NoError(t, err)
		require.NotEmpty(t, txid)

		// unroll the spent VTXO to put checkpoint onchain
		expl, err := mempool_explorer.NewExplorer(
			"http://localhost:3000", arklib.BitcoinRegTest,
			mempool_explorer.WithTracker(false))
		require.NoError(t, err)

		branch, err := redemption.NewRedeemBranch(ctx, expl, setupIndexer(t), vtxo)
		require.NoError(t, err)

		for parentTx, err := branch.NextRedeemTx(); err == nil; parentTx, err = branch.NextRedeemTx() {
			bumpAndBroadcastTx(t, parentTx, expl)
		}

		// give some time for the server to process the unroll and broadcast the checkpoint
		time.Sleep(5 * time.Second)

		// generate 20 blocks to expire the checkpoint output
		err = generateBlocks(20)
		require.NoError(t, err)

		// give time for the server to process the sweep
		time.Sleep(20 * time.Second)

		// verify that the checkpoint output has been put onchain
		// and that the VTXO has been swept
		spendable, spent, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, spendable)
		require.NotEmpty(t, spent)
		require.Len(t, spent, 1)
		require.Equal(t, txid, spendable[0].Txid)
		require.Equal(t, vtxo.Txid, spent[0].Txid)
		require.True(t, spent[0].Swept)
		require.True(t, spent[0].Spent)
		require.True(t, spent[0].Unrolled)
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
		txid, err := alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddr, Amount: 1000}})
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
		ctx, false, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()
	require.NoError(t, incomingErr)

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
		ctx, false, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()
	require.NoError(t, incomingErr)

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

// TestDeleteIntent tests deleting an already registered intent
func TestDeleteIntent(t *testing.T) {
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

	// should fail becasue no intent is associated with the vtxos
	err = alice.DeleteIntent(ctx, aliceVtxos, []types.Utxo{}, nil)
	require.Error(t, err)
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
	_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{{
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
	// to implement some sort of deadline for the delagate to register it if needed.
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
		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{
			{
				Amount: aliceVtxo.Amount,
				To:     aliceAddr,
			},
		})
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
		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{
			{
				Amount: aliceVtxo.Amount,
				To:     aliceAddr,
			},
		})
		require.Error(t, err)
	})

	t.Run("failed to submit valid tree sigantures", func(t *testing.T) {
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
		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{
			{
				Amount: aliceVtxo.Amount,
				To:     aliceAddr,
			},
		})
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
		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{
			{
				Amount: aliceVtxo.Amount,
				To:     aliceAddr,
			},
		})
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
		_, err = alice.SendOffChain(t.Context(), false, []types.Receiver{
			{
				Amount: aliceVtxo.Amount,
				To:     aliceAddr,
			},
		})
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
