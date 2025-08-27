package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/arkade-os/go-sdk/explorer"
	"github.com/arkade-os/go-sdk/indexer"
	grpcindexer "github.com/arkade-os/go-sdk/indexer/grpc"
	"github.com/arkade-os/go-sdk/redemption"
	"github.com/arkade-os/go-sdk/store"
	inmemorystoreconfig "github.com/arkade-os/go-sdk/store/inmemory"
	"github.com/arkade-os/go-sdk/types"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	password      = "password"
	redeemAddress = "bcrt1q2wrgf2hrkfegt0t97cnv4g5yvfjua9k6vua54d"
)

func TestMain(m *testing.M) {
	if err := generateBlock(); err != nil {
		log.Fatalf("error generating block: %s", err)
	}

	err := setupServerWalletAndCLI()
	if err != nil && !errors.Is(err, ErrAlreadySetup) {
		log.Fatalf("error setting up server wallet and CLI: %s", err)
	}
	time.Sleep(1 * time.Second)

	code := m.Run()
	os.Exit(code)
}

func TestSettleInSameRound(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer alice.Stop()
	defer grpcAlice.Close()

	bob, grpcBob := setupArkSDK(t)
	defer bob.Stop()
	defer grpcBob.Close()

	_, aliceAddr, aliceBoardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	_, bobAddr, bobBoardingAddress, err := bob.Receive(ctx)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", aliceBoardingAddress)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", bobBoardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	var aliceRoundID, bobRoundID string
	var aliceErr, bobErr error

	go func() {
		defer wg.Done()

		wwg := &sync.WaitGroup{}
		wwg.Add(1)
		go func() {
			//nolint:all
			alice.NotifyIncomingFunds(ctx, aliceAddr)
			wwg.Done()
		}()
		aliceRoundID, aliceErr = alice.Settle(ctx)
		wwg.Wait()
	}()

	go func() {
		defer wg.Done()

		wwg := &sync.WaitGroup{}
		wwg.Add(1)
		go func() {
			defer wwg.Done()
			vtxos, err := bob.NotifyIncomingFunds(ctx, bobAddr)
			require.NoError(t, err)
			require.NotEmpty(t, vtxos)
		}()
		bobRoundID, bobErr = bob.Settle(ctx)
		wwg.Wait()
	}()

	wg.Wait()

	require.NoError(t, aliceErr)
	require.NoError(t, bobErr)
	require.NotEmpty(t, aliceRoundID)
	require.NotEmpty(t, bobRoundID)
	require.Equal(t, aliceRoundID, bobRoundID)

	time.Sleep(5 * time.Second)

	aliceVtxos, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceVtxos)

	bobVtxos, _, err := bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobVtxos)

	_, aliceOffchainAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	// Alice sends to Bob
	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := alice.NotifyIncomingFunds(ctx, bobOffchainAddr)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
	}()
	_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobOffchainAddr, Amount: 5000}})
	require.NoError(t, err)

	wg.Wait()

	// Bob sends to Alice
	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := bob.NotifyIncomingFunds(ctx, aliceOffchainAddr)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
	}()
	_, err = bob.SendOffChain(ctx, false, []types.Receiver{{To: aliceOffchainAddr, Amount: 3000}})
	require.NoError(t, err)

	wg.Wait()

	wg.Add(2)

	var aliceSecondRoundID, bobSecondRoundID string

	go func() {
		defer wg.Done()

		wwg := &sync.WaitGroup{}
		wwg.Add(1)
		go func() {
			//nolint:all
			alice.NotifyIncomingFunds(ctx, aliceAddr)
			wwg.Done()
		}()
		aliceSecondRoundID, aliceErr = alice.Settle(ctx)
		wwg.Wait()
	}()

	go func() {
		defer wg.Done()

		wwg := &sync.WaitGroup{}
		wwg.Add(1)
		go func() {
			//nolint:all
			alice.NotifyIncomingFunds(ctx, aliceAddr)
			wwg.Done()
		}()
		bobSecondRoundID, bobErr = bob.Settle(ctx)
		wwg.Wait()
	}()

	wg.Wait()

	require.NoError(t, aliceErr)
	require.NoError(t, bobErr)
	require.Equal(t, aliceSecondRoundID, bobSecondRoundID, "Second settle round IDs should match")

	time.Sleep(5 * time.Second)

	aliceVtxosAfter, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceVtxosAfter)

	bobVtxosAfter, _, err := bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobVtxosAfter)

	var aliceNewVtxo, bobNewVtxo types.Vtxo
	for _, vtxo := range aliceVtxosAfter {
		if slices.Contains(vtxo.CommitmentTxids, aliceSecondRoundID) {
			aliceNewVtxo = vtxo
			break
		}
	}
	for _, vtxo := range bobVtxosAfter {
		if slices.Contains(vtxo.CommitmentTxids, bobSecondRoundID) {
			bobNewVtxo = vtxo
			break
		}
	}

	require.NotEmpty(t, aliceNewVtxo)
	require.NotEmpty(t, bobNewVtxo)
	require.Equal(t, aliceNewVtxo.CommitmentTxids, bobNewVtxo.CommitmentTxids)
}

func TestUnilateralExit(t *testing.T) {
	t.Run("leaf vtxo", func(t *testing.T) {
		var receive arkReceive
		receiveStr, err := runArkCommand("receive")
		require.NoError(t, err)

		err = json.Unmarshal([]byte(receiveStr), &receive)
		require.NoError(t, err)

		_, err = runCommand("nigiri", "faucet", receive.Boarding)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		_, err = runArkCommand("settle", "--password", password)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		var balance arkBalance
		balanceStr, err := runArkCommand("balance")
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
		require.NotZero(t, balance.Offchain.Total)

		_, err = runCommand("nigiri", "faucet", receive.Onchain)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		_, err = runArkCommand("redeem", "--force", "--password", password)
		require.NoError(t, err)

		err = generateBlock()
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		balanceStr, err = runArkCommand("balance")
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
		require.Zero(t, balance.Offchain.Total)
		require.Greater(t, len(balance.Onchain.Locked), 0)

		lockedBalance := balance.Onchain.Locked[0].Amount
		require.NotZero(t, lockedBalance)
	})

	t.Run("preconfirmed vtxo", func(t *testing.T) {
		var receive arkReceive
		receiveStr, err := runArkCommand("receive")
		require.NoError(t, err)

		err = json.Unmarshal([]byte(receiveStr), &receive)
		require.NoError(t, err)

		_, err = runCommand("nigiri", "faucet", receive.Boarding, "0.00001")
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		_, err = runArkCommand("settle", "--password", password)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		_, err = runArkCommand(
			"send", "--to", receive.Offchain, "--amount", "1000", "--password", password,
		)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		var balance arkBalance
		balanceStr, err := runArkCommand("balance")
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
		require.NotZero(t, balance.Offchain.Total)

		_, err = runCommand("nigiri", "faucet", receive.Onchain)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		_, err = runArkCommand("redeem", "--force", "--password", password)
		require.NoError(t, err)

		// generate bunch of blocks to make sure also the checkpoints are confirmed
		err = generateBlocks(5)
		require.NoError(t, err)

		_, err = runArkCommand("redeem", "--force", "--password", password)
		require.NoError(t, err)

		err = generateBlocks(1)
		require.NoError(t, err)

		balanceStr, err = runArkCommand("balance")
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
		require.Zero(t, balance.Offchain.Total)
		require.Greater(t, len(balance.Onchain.Locked), 0)

		lockedBalance := balance.Onchain.Locked[0].Amount
		require.NotZero(t, lockedBalance)
	})
}

func TestCollaborativeExit(t *testing.T) {
	t.Run("with vtxo change", func(t *testing.T) {
		var receive arkReceive
		receiveStr, err := runArkCommand("receive")
		require.NoError(t, err)

		err = json.Unmarshal([]byte(receiveStr), &receive)
		require.NoError(t, err)

		_, err = runCommand("nigiri", "faucet", receive.Boarding, "0.00010000")
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		_, err = runArkCommand("settle", "--password", password)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		// Redeem 1000 satoshis onchain, keep 9000 satoshis offchain
		_, err = runArkCommand(
			"redeem", "--amount", "1000", "--address", redeemAddress, "--password", password,
		)
		require.NoError(t, err)
	})

	t.Run("without vtxo change", func(t *testing.T) {
		var receive arkReceive
		receiveStr, err := runArkCommand("receive")
		require.NoError(t, err)

		err = json.Unmarshal([]byte(receiveStr), &receive)
		require.NoError(t, err)

		_, err = runCommand("nigiri", "faucet", receive.Boarding, "0.00010000")
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		_, err = runArkCommand("settle", "--password", password)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		// Redeem 10000 satoshis onchain
		_, err = runArkCommand(
			"redeem",
			"--amount", "10000", "--address", redeemAddress, "--password", password,
		)
		require.NoError(t, err)
	})
}

func TestReactToRedemptionOfRefreshedVtxos(t *testing.T) {
	ctx := context.Background()
	indexerSvc := setupIndexer(t)
	sdkClient, grpcClient := setupArkSDK(t)
	defer sdkClient.Stop()
	defer grpcClient.Close()

	_, arkAddr, boardingAddress, err := sdkClient.Receive(ctx)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := sdkClient.NotifyIncomingFunds(ctx, arkAddr)
		require.NoError(t, err)
		require.NotNil(t, vtxos)
	}()
	roundId, err := sdkClient.Settle(ctx)
	require.NoError(t, err)

	wg.Wait()
	time.Sleep(4 * time.Second)

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
		if !v.Preconfirmed && v.CommitmentTxids[0] == roundId {
			vtxo = v
			break
		}
	}

	expl := explorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)

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
}

func TestReactToRedemptionOfVtxosSpentAsync(t *testing.T) {
	t.Run("default vtxo script", func(t *testing.T) {
		ctx := context.Background()
		indexerSvc := setupIndexer(t)
		sdkClient, grpcClient := setupArkSDK(t)
		defer sdkClient.Stop()
		defer grpcClient.Close()

		_, offchainAddress, boardingAddress, err := sdkClient.Receive(ctx)
		require.NoError(t, err)

		_, err = runCommand("nigiri", "faucet", boardingAddress)
		require.NoError(t, err)

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

		err = generateBlock()
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

		time.Sleep(4 * time.Second)

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

		expl := explorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)

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
		alice, grpcTransportClient := setupArkSDK(t)

		defer alice.Stop()
		defer grpcTransportClient.Close()

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

		_, err = runCommand("nigiri", "faucet", boardingAddress)
		require.NoError(t, err)

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

		time.Sleep(4 * time.Second)

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

		infos, err := grpcTransportClient.GetInfo(ctx)
		require.NoError(t, err)

		unilateralExitDelayType := arklib.LocktimeTypeSecond
		if infos.UnilateralExitDelay < 512 {
			unilateralExitDelayType = arklib.LocktimeTypeBlock
		}

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
			&script.CSVMultisigClosure{
				Locktime: arklib.RelativeLocktime{
					Type:  unilateralExitDelayType,
					Value: uint32(infos.UnilateralExitDelay),
				},
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{aliceAddr.Signer},
				},
			},
		)
		require.NoError(t, err)

		explorer := explorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)

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
			err = generateBlock()
			require.NoError(t, err)
		}

		bobTxid, _, signedCheckpoints, err := grpcTransportClient.SubmitTx(
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

		err = grpcTransportClient.FinalizeTx(ctx, bobTxid, finalCheckpoints)
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
}

func TestChainOffchainTransactions(t *testing.T) {
	var receive arkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runArkCommand("settle", "--password", password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runArkCommand(
		"send", "--amount", "10000", "--to", receive.Offchain, "--password", password,
	)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	var balance arkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)

	_, err = runArkCommand(
		"send", "--amount", "10000", "--to", receive.Offchain, "--password", password,
	)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
}

func TestSubDustVtxoTransaction(t *testing.T) {
	ctx := context.Background()
	bob, grpcBob := setupArkSDK(t)
	defer bob.Stop()
	defer grpcBob.Close()

	var receive arkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runArkCommand("settle", "--password", password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, bobAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	subdustAmount := uint64(1)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := bob.NotifyIncomingFunds(ctx, bobAddr)
		require.NoError(t, err)
		require.NotNil(t, vtxos)
		require.Len(t, vtxos, 1)
		require.Equal(t, vtxos[0].Amount, subdustAmount)
	}()

	// send 1 satoshi
	_, err = runArkCommand(
		"send", "--amount", fmt.Sprintf("%d", subdustAmount),
		"--to", bobAddr, "--password", password,
	)
	require.NoError(t, err)

	// wait for bob to receive the vtxo
	wg.Wait()

	// bob should fail to send the satoshi via offchain tx
	_, err = bob.SendOffChain(ctx, false, []types.Receiver{{To: bobAddr, Amount: subdustAmount}})
	require.Error(t, err)

	// bob should fail to settle the subdust
	_, err = bob.Settle(ctx, arksdk.WithSubDustVtxos)
	require.Error(t, err)

	// resend some funds to bob so he can settle
	_, err = runArkCommand(
		"send", "--amount", "1000", "--to", bobAddr, "--password", password,
	)
	require.NoError(t, err)

	// now that bob has enough funds (greater than dust), he should be able to settle
	_, err = bob.Settle(ctx, arksdk.WithSubDustVtxos)
	require.NoError(t, err)
}

// TestCollisionBetweenInRoundAndRedeemVtxo tests for a potential collision between VTXOs that could occur
// due to a race condition between simultaneous Settle and SubmitRedeemTx calls. The race condition doesn't
// consistently reproduce, making the test unreliable in automated test suites. Therefore, the test is skipped
// by default and left here as documentation for future debugging and reference.
func TestCollisionBetweenInRoundAndRedeemVtxo(t *testing.T) {
	t.Skip()

	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer alice.Stop()
	defer grpcAlice.Close()

	bob, grpcBob := setupArkSDK(t)
	defer bob.Stop()
	defer grpcBob.Close()

	_, _, aliceBoardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	_, bobAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", aliceBoardingAddress, "0.00005000")
	require.NoError(t, err)

	_, err = runCommand("nigiri", "rpc", "--generate", "1")
	require.NoError(t, err)
	time.Sleep(5 * time.Second)

	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	//test collision when first Settle is called
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
	time.Sleep(50 * time.Millisecond)
	go func() {
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

func TestAliceSendsSeveralTimesToBob(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer alice.Stop()
	defer grpcAlice.Close()

	bob, grpcBob := setupArkSDK(t)
	defer bob.Stop()
	defer grpcBob.Close()

	_, aliceAddr, boardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := alice.NotifyIncomingFunds(ctx, aliceAddr)
		require.NoError(t, err)
		require.NotNil(t, vtxos)
	}()
	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	wg.Wait()

	_, bobAddress, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := alice.NotifyIncomingFunds(ctx, bobAddress)
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
		vtxos, err := alice.NotifyIncomingFunds(ctx, bobAddress)
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
		vtxos, err := alice.NotifyIncomingFunds(ctx, bobAddress)
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
		vtxos, err := alice.NotifyIncomingFunds(ctx, bobAddress)
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
	require.Len(t, uniqueVtxos, 4)

	require.NoError(t, err)
}

func TestRedeemNotes(t *testing.T) {
	note := generateNote(t, 10_000)

	balanceBeforeStr, err := runArkCommand("balance")
	require.NoError(t, err)

	var balanceBefore arkBalance
	require.NoError(t, json.Unmarshal([]byte(balanceBeforeStr), &balanceBefore))

	_, err = runArkCommand("redeem-notes", "--notes", note, "--password", password)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	balanceAfterStr, err := runArkCommand("balance")
	require.NoError(t, err)

	var balanceAfter arkBalance
	require.NoError(t, json.Unmarshal([]byte(balanceAfterStr), &balanceAfter))

	require.Greater(t, balanceAfter.Offchain.Total, balanceBefore.Offchain.Total)

	_, err = runArkCommand("redeem-notes", "--notes", note, "--password", password)
	require.Error(t, err)
}

func TestSendArkTxWithSeveralInputs(t *testing.T) {
	const numberOfInputs = 5
	const amountPerInput = 1_000

	alice, grpcAlice := setupArkSDK(t)
	defer alice.Stop()
	defer grpcAlice.Close()

	ctx := context.Background()

	for i := 0; i < numberOfInputs; i++ {
		note := generateNote(t, amountPerInput)
		_, err := alice.RedeemNotes(ctx, []string{note})
		require.NoError(t, err)
	}

	aliceVtxos, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, aliceVtxos, numberOfInputs)

	_, aliceOffchainAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)

	txid, err := alice.SendOffChain(
		ctx,
		false,
		[]types.Receiver{{To: aliceOffchainAddr, Amount: amountPerInput * numberOfInputs}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)
}

func TestSendToCLTVMultisigClosure(t *testing.T) {
	ctx := context.Background()
	indexerSvc := setupIndexer(t)
	alice, grpcAlice := setupArkSDK(t)
	defer alice.Stop()
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
	_, offchainAddr, boardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

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

	const cltvBlocks = 10
	const sendAmount = 10000

	currentHeight, err := getBlockHeight()
	require.NoError(t, err)

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

	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := alice.NotifyIncomingFunds(ctx, bobAddrStr)
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

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	unilateralExitDelayType := arklib.LocktimeTypeSecond
	if infos.UnilateralExitDelay < 512 {
		unilateralExitDelayType = arklib.LocktimeTypeBlock
	}

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
		&script.CSVMultisigClosure{
			Locktime: arklib.RelativeLocktime{
				Type:  unilateralExitDelayType,
				Value: uint32(infos.UnilateralExitDelay),
			},
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{aliceAddr.Signer},
			},
		},
	)
	require.NoError(t, err)

	explorer := explorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)

	encodedVirtualTx, err := ptx.B64Encode()
	require.NoError(t, err)

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

	// should fail because the tx is not yet valid
	_, _, _, err = grpcAlice.SubmitTx(ctx, signedTx, checkpoints)
	require.Error(t, err)

	// Generate blocks to pass the timelock
	for range cltvBlocks {
		err = generateBlock()
		require.NoError(t, err)
	}

	// should succeed now
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

func TestSendToConditionMultisigClosure(t *testing.T) {
	ctx := context.Background()
	indexerSvc := setupIndexer(t)
	alice, grpcAlice := setupArkSDK(t)
	defer alice.Stop()
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
	_, offchainAddr, boardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

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

	const sendAmount = 10000

	preimage := make([]byte, 32)
	_, err = rand.Read(preimage)
	require.NoError(t, err)

	sha256Hash := sha256.Sum256(preimage)

	// script commiting to the preimage
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
	checkpointClosure := vtxoScript.ForfeitClosures()[1]

	bobAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     aliceAddr.Signer,
	}

	scriptBytes, err := closure.Script()
	require.NoError(t, err)

	checkpointScript, err := checkpointClosure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	checkpointMerkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(checkpointScript).TapHash(),
	)
	require.NoError(t, err)

	checkpointCtrlBlock, err := txscript.ParseControlBlock(checkpointMerkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	checkpointTapscript := &waddrmgr.Tapscript{
		ControlBlock:   checkpointCtrlBlock,
		RevealedScript: checkpointMerkleProof.Script,
	}

	bobAddrStr, err := bobAddr.EncodeV0()
	require.NoError(t, err)

	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := alice.NotifyIncomingFunds(ctx, bobAddrStr)
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

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	unilateralExitDelayType := arklib.LocktimeTypeSecond
	if infos.UnilateralExitDelay < 512 {
		unilateralExitDelayType = arklib.LocktimeTypeBlock
	}

	ptx, checkpointsPtx, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  virtualPtx.UnsignedTx.TxHash(),
					Index: bobOutputIndex,
				},
				Amount:              bobOutput.Value,
				Tapscript:           tapscript,
				CheckpointTapscript: checkpointTapscript,
				RevealedTapscripts:  tapscripts,
			},
		},
		[]*wire.TxOut{
			{
				Value:    bobOutput.Value,
				PkScript: alicePkScript,
			},
		},
		&script.CSVMultisigClosure{
			Locktime: arklib.RelativeLocktime{
				Type:  unilateralExitDelayType,
				Value: uint32(infos.UnilateralExitDelay),
			},
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{aliceAddr.Signer},
			},
		},
	)
	require.NoError(t, err)

	explorer := explorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)

	encodedVirtualTx, err := ptx.B64Encode()
	require.NoError(t, err)

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

	bobTxid, _, signedCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, checkpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedCheckpoints))
	for _, checkpoint := range signedCheckpoints {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		require.NoError(t, err)

		err = txutils.AddConditionWitness(0, ptx, wire.TxWitness{preimage[:]})
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

func TestDeleteIntent(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer alice.Stop()
	defer grpcAlice.Close()

	// faucet offchain address
	_, offchainAddr, boardingAddr, err := alice.Receive(ctx)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddr, "0.0002")
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		vtxos, err := alice.NotifyIncomingFunds(ctx, offchainAddr)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
	}()

	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	wg.Wait()

	aliceVtxos, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceVtxos)

	_, err = alice.RegisterIntent(ctx, aliceVtxos, []types.Utxo{}, nil, nil, nil)
	require.NoError(t, err)

	// should fail because previous intent spend same vtxos
	_, err = alice.RegisterIntent(ctx, aliceVtxos, []types.Utxo{}, nil, nil, nil)
	require.Error(t, err)

	// should delete the intent
	err = alice.DeleteIntent(ctx, aliceVtxos, []types.Utxo{}, nil)
	require.NoError(t, err)

	// should fail becasue no intent is associated with the vtxos
	err = alice.DeleteIntent(ctx, aliceVtxos, []types.Utxo{}, nil)
	require.Error(t, err)
}

func TestSweep(t *testing.T) {
	var receive arkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runArkCommand("settle", "--password", password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runCommand("nigiri", "rpc", "--generate", "30")
	require.NoError(t, err)

	time.Sleep(20 * time.Second)

	var balance arkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total) // all funds should be swept

	// redeem the note
	_, err = runArkCommand("recover", "--password", password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total) // funds should be recovered
}

func runArkCommand(arg ...string) (string, error) {
	args := append([]string{"ark"}, arg...)
	return runDockerExec("arkd", args...)
}

var ErrAlreadySetup = errors.New("already setup")

func setupServerWalletAndCLI() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	// skip if already setup
	resp, err := http.NewRequest("GET", "http://localhost:7070/v1/info", nil)
	if resp.Response != nil && err == nil {
		return ErrAlreadySetup
	}

	req, err := http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/seed", nil)
	if err != nil {
		return fmt.Errorf("failed to prepare generate seed request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

	seedResp, err := adminHttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to generate seed: %s", err)
	}

	var seed struct {
		Seed string `json:"seed"`
	}

	if err := json.NewDecoder(seedResp.Body).Decode(&seed); err != nil {
		return fmt.Errorf("failed to parse response: %s", err)
	}

	reqBody := bytes.NewReader(
		[]byte(fmt.Sprintf(`{"seed": "%s", "password": "%s"}`, seed.Seed, password)),
	)
	req, err = http.NewRequest("POST", "http://localhost:7070/v1/admin/wallet/create", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet create request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to create wallet: %s", err)
	}

	reqBody = bytes.NewReader([]byte(fmt.Sprintf(`{"password": "%s"}`, password)))
	req, err = http.NewRequest("POST", "http://localhost:7070/v1/admin/wallet/unlock", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet unlock request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	var status struct {
		Initialized bool `json:"initialized"`
		Unlocked    bool `json:"unlocked"`
		Synced      bool `json:"synced"`
	}
	for {
		time.Sleep(time.Second)

		req, err := http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/status", nil)
		if err != nil {
			return fmt.Errorf("failed to prepare status request: %s", err)
		}
		resp, err := adminHttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get status: %s", err)
		}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return fmt.Errorf("failed to parse status response: %s", err)
		}
		if status.Initialized && status.Unlocked && status.Synced {
			break
		}
	}

	var addr struct {
		Address string `json:"address"`
	}
	for addr.Address == "" {
		time.Sleep(time.Second)

		req, err = http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/address", nil)
		if err != nil {
			return fmt.Errorf("failed to prepare new address request: %s", err)
		}
		req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

		resp, err := adminHttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get new address: %s", err)
		}

		if err := json.NewDecoder(resp.Body).Decode(&addr); err != nil {
			return fmt.Errorf("failed to parse response: %s", err)
		}
	}

	const numberOfFaucet = 15 // must cover the liquidity needed for all tests

	for i := 0; i < numberOfFaucet; i++ {
		_, err = runCommand("nigiri", "faucet", addr.Address)
		if err != nil {
			return fmt.Errorf("failed to fund wallet: %s", err)
		}
	}

	time.Sleep(5 * time.Second)

	if _, err := runArkCommand(
		"init", "--server-url", "localhost:7070", "--password", password,
		"--network", "regtest", "--explorer", "http://chopsticks:3000",
	); err != nil {
		return fmt.Errorf("error initializing ark config: %s", err)
	}
	return nil
}

func setupArkSDK(t *testing.T) (arksdk.ArkClient, client.TransportClient) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
		AppDataStoreType: types.KVStore,
	})
	require.NoError(t, err)

	client, err := arksdk.NewArkClient(appDataStore)
	require.NoError(t, err)

	err = client.Init(context.Background(), arksdk.InitArgs{
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  "localhost:7070",
		Password:   password,
	})
	require.NoError(t, err)

	err = client.Unlock(context.Background(), password)
	require.NoError(t, err)

	grpcClient, err := grpcclient.NewClient("localhost:7070")
	require.NoError(t, err)

	return client, grpcClient
}

func setupIndexer(t *testing.T) indexer.Indexer {
	svc, err := grpcindexer.NewClient("localhost:7070")
	require.NoError(t, err)
	return svc
}

func generateNote(t *testing.T, amount uint32) string {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", "http://localhost:7070/v1/admin/note", reqBody)
	if err != nil {
		t.Fatalf("failed to prepare note request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	resp, err := adminHttpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create note: %s", err)
	}

	var noteResp struct {
		Notes []string `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&noteResp); err != nil {
		t.Fatalf("failed to parse response: %s", err)
	}

	return noteResp.Notes[0]
}
