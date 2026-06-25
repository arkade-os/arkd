package application

import (
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// randomTapKey generates a valid 32-byte x-only pubkey as 64 hex chars.
func randomTapKey(t *testing.T) string {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
}

// p2trScriptBytes returns the raw P2TR script bytes for a tapkey hex string.
func p2trScriptBytes(t *testing.T, tapKeyHex string) []byte {
	t.Helper()
	b, err := hex.DecodeString(tapKeyHex)
	require.NoError(t, err)
	pk, err := schnorr.ParsePubKey(b)
	require.NoError(t, err)
	s, err := arkscript.P2TRScript(pk)
	require.NoError(t, err)
	return s
}

// checkpointPsbtB64 builds a base64 PSBT whose first (and only) output has
// the given pkscript, matching the shape restore/stop parses from the DB.
func checkpointPsbtB64(t *testing.T, firstOutputPkScript []byte) string {
	t.Helper()
	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: chainhash.Hash{}, Index: 0}},
		[]*wire.TxOut{{Value: 1000, PkScript: firstOutputPkScript}},
		3, 0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

// arkTxPsbtB64 builds a base64 PSBT whose outputs are the given pkscripts.
// decodeTx extracts vtxos from these outputs (PubKey = PkScript[2:]).
func arkTxPsbtB64(t *testing.T, outputScripts [][]byte) string {
	t.Helper()
	outs := make([]*wire.TxOut, 0, len(outputScripts))
	for _, s := range outputScripts {
		outs = append(outs, &wire.TxOut{Value: 1000000, PkScript: s})
	}
	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: chainhash.Hash{}, Index: 0}},
		outs,
		3, 0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

// vtxoScriptHex matches the service's fmt.Sprintf("5120%s", key) for vtxo
// tapkeys.
func vtxoScriptHex(tapKeyHex string) string {
	return fmt.Sprintf("5120%s", tapKeyHex)
}

// ckptScriptHex matches the service's hex.EncodeToString(TxOut[0].PkScript)
// for checkpoint txs.
func ckptScriptHex(t *testing.T, tapKeyHex string) string {
	t.Helper()
	return hex.EncodeToString(p2trScriptBytes(t, tapKeyHex))
}

func TestRestoreWatchingVtxos(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		k1 := randomTapKey(t)
		k2 := randomTapKey(t)
		k3 := randomTapKey(t)
		k4 := randomTapKey(t)

		rounds := &mockedRoundRepo{}
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rounds.On("GetSweepableRounds", mock.Anything).Return([]string{"r1"}, nil)
		vtxos.On("GetVtxoPubKeysByCommitmentTxids", mock.Anything, []string{"r1"}, uint64(0)).
			Return([]string{k1, k2}, nil)
		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, []string{k1, k2}).
			Return([]domain.Tx{
				{Txid: "txA", Str: checkpointPsbtB64(t, p2trScriptBytes(t, k3))},
				{Txid: "txB", Str: checkpointPsbtB64(t, p2trScriptBytes(t, k4))},
			}, nil)
		rm.On("Rounds").Return(rounds)
		rm.On("Vtxos").Return(vtxos)
		scn.On("WatchScripts", mock.Anything, mock.Anything).Return(nil)

		svc := &service{repoManager: rm, scanner: scn}
		require.NoError(t, svc.restoreWatchingVtxos())

		require.ElementsMatch(t, []string{
			vtxoScriptHex(k1), vtxoScriptHex(k2),
			ckptScriptHex(t, k3), ckptScriptHex(t, k4),
		}, scn.Watched())
		scn.AssertNumberOfCalls(t, "WatchScripts", 1)
		vtxos.AssertNumberOfCalls(t, "GetCheckpointTxsByVtxoPubKeys", 1)
	})

	t.Run("no_sweepable_rounds", func(t *testing.T) {
		rounds := &mockedRoundRepo{}
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rounds.On("GetSweepableRounds", mock.Anything).Return([]string{}, nil)
		rm.On("Rounds").Return(rounds)
		rm.On("Vtxos").Return(vtxos)

		svc := &service{repoManager: rm, scanner: scn}
		require.NoError(t, svc.restoreWatchingVtxos())

		require.Empty(t, scn.Watched())
		scn.AssertNumberOfCalls(t, "WatchScripts", 0)
		vtxos.AssertNumberOfCalls(t, "GetVtxoPubKeysByCommitmentTxids", 0)
		vtxos.AssertNumberOfCalls(t, "GetCheckpointTxsByVtxoPubKeys", 0)
	})

	t.Run("tapkeys_empty", func(t *testing.T) {
		rounds := &mockedRoundRepo{}
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rounds.On("GetSweepableRounds", mock.Anything).Return([]string{"r1"}, nil)
		vtxos.On("GetVtxoPubKeysByCommitmentTxids", mock.Anything, []string{"r1"}, uint64(0)).
			Return([]string{}, nil)
		rm.On("Rounds").Return(rounds)
		rm.On("Vtxos").Return(vtxos)

		svc := &service{repoManager: rm, scanner: scn}
		require.NoError(t, svc.restoreWatchingVtxos())

		require.Empty(t, scn.Watched())
		scn.AssertNumberOfCalls(t, "WatchScripts", 0)
		vtxos.AssertNumberOfCalls(t, "GetCheckpointTxsByVtxoPubKeys", 0)
	})

	t.Run("ckpt_fetch_err_soft_fail", func(t *testing.T) {
		k1 := randomTapKey(t)
		k2 := randomTapKey(t)

		rounds := &mockedRoundRepo{}
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rounds.On("GetSweepableRounds", mock.Anything).Return([]string{"r1"}, nil)
		vtxos.On("GetVtxoPubKeysByCommitmentTxids", mock.Anything, []string{"r1"}, uint64(0)).
			Return([]string{k1, k2}, nil)
		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, mock.Anything).
			Return(nil, fmt.Errorf("db down"))
		rm.On("Rounds").Return(rounds)
		rm.On("Vtxos").Return(vtxos)
		scn.On("WatchScripts", mock.Anything, mock.Anything).Return(nil)

		svc := &service{repoManager: rm, scanner: scn}
		require.NoError(t, svc.restoreWatchingVtxos())

		// vtxo scripts still watched, no checkpoint scripts.
		require.ElementsMatch(t, []string{
			vtxoScriptHex(k1), vtxoScriptHex(k2),
		}, scn.Watched())
		scn.AssertNumberOfCalls(t, "WatchScripts", 1)
	})

	t.Run("unparseable_ckpt_psbt_skipped", func(t *testing.T) {
		k1 := randomTapKey(t)
		k3 := randomTapKey(t)

		rounds := &mockedRoundRepo{}
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rounds.On("GetSweepableRounds", mock.Anything).Return([]string{"r1"}, nil)
		vtxos.On("GetVtxoPubKeysByCommitmentTxids", mock.Anything, []string{"r1"}, uint64(0)).
			Return([]string{k1}, nil)
		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, mock.Anything).
			Return([]domain.Tx{
				{Txid: "garbage", Str: "not-a-psbt"},
				{Txid: "good", Str: checkpointPsbtB64(t, p2trScriptBytes(t, k3))},
			}, nil)
		rm.On("Rounds").Return(rounds)
		rm.On("Vtxos").Return(vtxos)
		scn.On("WatchScripts", mock.Anything, mock.Anything).Return(nil)

		svc := &service{repoManager: rm, scanner: scn}
		require.NoError(t, svc.restoreWatchingVtxos())

		require.ElementsMatch(t, []string{
			vtxoScriptHex(k1), ckptScriptHex(t, k3),
		}, scn.Watched())
	})

	t.Run("bad_tapkey_hex_filtered", func(t *testing.T) {
		k1 := randomTapKey(t)
		k3 := randomTapKey(t)
		badKey := "abcd"

		rounds := &mockedRoundRepo{}
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rounds.On("GetSweepableRounds", mock.Anything).Return([]string{"r1"}, nil)
		vtxos.On("GetVtxoPubKeysByCommitmentTxids", mock.Anything, []string{"r1"}, uint64(0)).
			Return([]string{badKey, k1}, nil)
		// restore passes raw tapKeys (unfiltered) to the ckpt fetch.
		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, []string{badKey, k1}).
			Return([]domain.Tx{
				{Txid: "txA", Str: checkpointPsbtB64(t, p2trScriptBytes(t, k3))},
			}, nil)
		rm.On("Rounds").Return(rounds)
		rm.On("Vtxos").Return(vtxos)
		scn.On("WatchScripts", mock.Anything, mock.Anything).Return(nil)

		svc := &service{repoManager: rm, scanner: scn}
		require.NoError(t, svc.restoreWatchingVtxos())

		require.ElementsMatch(t, []string{
			vtxoScriptHex(k1), ckptScriptHex(t, k3),
		}, scn.Watched())
	})
}

func TestStopWatchingVtxos(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		k1 := randomTapKey(t)
		k2 := randomTapKey(t)
		k3 := randomTapKey(t)

		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, []string{k1, k2}).
			Return([]domain.Tx{
				{Txid: "txA", Str: checkpointPsbtB64(t, p2trScriptBytes(t, k3))},
			}, nil)
		rm.On("Vtxos").Return(vtxos)
		scn.On("UnwatchScripts", mock.Anything, mock.Anything).Return(nil)

		svc := &service{repoManager: rm, scanner: scn}
		svc.stopWatchingVtxos([]string{k1, k2})

		require.ElementsMatch(t, []string{
			vtxoScriptHex(k1), vtxoScriptHex(k2), ckptScriptHex(t, k3),
		}, scn.Unwatched())
		scn.AssertNumberOfCalls(t, "UnwatchScripts", 1)
	})

	t.Run("ckpt_fetch_err_soft_fail", func(t *testing.T) {
		k1 := randomTapKey(t)
		k2 := randomTapKey(t)

		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, mock.Anything).
			Return(nil, fmt.Errorf("db down"))
		rm.On("Vtxos").Return(vtxos)
		scn.On("UnwatchScripts", mock.Anything, mock.Anything).Return(nil)

		svc := &service{repoManager: rm, scanner: scn}
		svc.stopWatchingVtxos([]string{k1, k2})

		require.ElementsMatch(t, []string{
			vtxoScriptHex(k1), vtxoScriptHex(k2),
		}, scn.Unwatched())
		scn.AssertNumberOfCalls(t, "UnwatchScripts", 1)
	})

	t.Run("empty_tapkeys", func(t *testing.T) {
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rm.On("Vtxos").Return(vtxos)

		svc := &service{repoManager: rm, scanner: scn}
		svc.stopWatchingVtxos([]string{})

		require.Empty(t, scn.Unwatched())
		scn.AssertNumberOfCalls(t, "UnwatchScripts", 0)
		vtxos.AssertNumberOfCalls(t, "GetCheckpointTxsByVtxoPubKeys", 0)
	})

	t.Run("unparseable_ckpt_psbt_skipped", func(t *testing.T) {
		k1 := randomTapKey(t)
		k3 := randomTapKey(t)

		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, mock.Anything).
			Return([]domain.Tx{
				{Txid: "garbage", Str: "not-a-psbt"},
				{Txid: "good", Str: checkpointPsbtB64(t, p2trScriptBytes(t, k3))},
			}, nil)
		rm.On("Vtxos").Return(vtxos)
		scn.On("UnwatchScripts", mock.Anything, mock.Anything).Return(nil)

		svc := &service{repoManager: rm, scanner: scn}
		svc.stopWatchingVtxos([]string{k1})

		require.ElementsMatch(t, []string{
			vtxoScriptHex(k1), ckptScriptHex(t, k3),
		}, scn.Unwatched())
	})

	t.Run("unwatch_retries_then_succeeds", func(t *testing.T) {
		k1 := randomTapKey(t)
		k3 := randomTapKey(t)

		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		vtxos.On("GetCheckpointTxsByVtxoPubKeys", mock.Anything, mock.Anything).
			Return([]domain.Tx{
				{Txid: "txA", Str: checkpointPsbtB64(t, p2trScriptBytes(t, k3))},
			}, nil)
		rm.On("Vtxos").Return(vtxos)
		// First call fails, second succeeds — retry loop sleeps 100ms then
		// breaks.
		scn.On("UnwatchScripts", mock.Anything, mock.Anything).
			Return(fmt.Errorf("transient")).Once()
		scn.On("UnwatchScripts", mock.Anything, mock.Anything).
			Return(nil).Once()

		svc := &service{repoManager: rm, scanner: scn}
		svc.stopWatchingVtxos([]string{k1})

		scn.AssertNumberOfCalls(t, "UnwatchScripts", 2)
	})
}

// newFinalizedOffchainTx builds a finalized OffchainTx with the given ark tx
// and checkpoint txs, replaying the Requested→Accepted→Finalized event chain.
func newFinalizedOffchainTx(t *testing.T, arkTxid, arkPsbt string, checkpointTxs map[string]string) domain.OffchainTx {
	t.Helper()
	ckptTxids := make(map[string]string, len(checkpointTxs))
	for txid := range checkpointTxs {
		ckptTxids[txid] = "commitment_" + txid
	}
	return *domain.NewOffchainTxFromEvents([]domain.Event{
		domain.OffchainTxRequested{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxRequested,
			},
			ArkTx:                 arkPsbt,
			UnsignedCheckpointTxs: checkpointTxs,
			StartingTimestamp:     time.Now().Unix(),
		},
		domain.OffchainTxAccepted{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxAccepted,
			},
			CommitmentTxids:     ckptTxids,
			FinalArkTx:          arkPsbt,
			SignedCheckpointTxs: checkpointTxs,
			RootCommitmentTxid:  "root",
			ExpiryTimestamp:     time.Now().Add(time.Hour).Unix(),
		},
		domain.OffchainTxFinalized{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxFinalized,
			},
			FinalCheckpointTxs: checkpointTxs,
			Timestamp:          time.Now().Unix(),
		},
	})
}

// newAcceptedOffchainTx builds an accepted (non-finalized) OffchainTx.
func newAcceptedOffchainTx(t *testing.T, arkTxid, arkPsbt string, checkpointTxs map[string]string) domain.OffchainTx {
	t.Helper()
	ckptTxids := make(map[string]string, len(checkpointTxs))
	for txid := range checkpointTxs {
		ckptTxids[txid] = "commitment_" + txid
	}
	return *domain.NewOffchainTxFromEvents([]domain.Event{
		domain.OffchainTxRequested{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxRequested,
			},
			ArkTx:                 arkPsbt,
			UnsignedCheckpointTxs: checkpointTxs,
			StartingTimestamp:     time.Now().Unix(),
		},
		domain.OffchainTxAccepted{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxAccepted,
			},
			CommitmentTxids:     ckptTxids,
			FinalArkTx:          arkPsbt,
			SignedCheckpointTxs: checkpointTxs,
			RootCommitmentTxid:  "root",
			ExpiryTimestamp:     time.Now().Add(time.Hour).Unix(),
		},
	})
}

func TestOffchainTxHandler_WatchesCheckpointScripts(t *testing.T) {
	t.Run("finalized_tx_watches_checkpoint_and_vtxo_scripts", func(t *testing.T) {
		k1 := randomTapKey(t) // vtxo owner (ark tx output)
		k2 := randomTapKey(t) // checkpoint output recipient

		arkPsbt := arkTxPsbtB64(t, [][]byte{p2trScriptBytes(t, k1)})
		ckptPsbt := checkpointPsbtB64(t, p2trScriptBytes(t, k2))
		ckptTxid := "checkpoint_txid_1"
		arkTxid := "ark_txid_1"

		offchainTx := newFinalizedOffchainTx(t, arkTxid, arkPsbt,
			map[string]string{ckptTxid: ckptPsbt})

		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}
		wallet := &mockedWallet{}

		vtxos.On("GetVtxos", mock.Anything, mock.Anything).
			Return([]domain.Vtxo{}, nil)
		wallet.On("GetDustAmount", mock.Anything).Return(uint64(330), nil)
		scn.On("WatchScripts", mock.Anything, mock.Anything).Return(nil)
		rm.On("Vtxos").Return(vtxos)

		svc := &service{
			repoManager:         rm,
			scanner:             scn,
			wallet:              wallet,
			transactionEventsCh: make(chan TransactionEvent, 64),
			indexerTxEventsCh:   make(chan TransactionEvent, 64),
			wg:                  &sync.WaitGroup{},
			offchainTxMu:        &sync.Mutex{},
		}
		svc.registerEventHandlers()
		rm.offchainTxHandler(offchainTx)

		expectedCkptScript := ckptScriptHex(t, k2)
		expectedVtxoScript := vtxoScriptHex(k1)
		require.Eventually(t, func() bool {
			return slices.Contains(scn.Watched(), expectedCkptScript) &&
				slices.Contains(scn.Watched(), expectedVtxoScript)
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("non_finalized_tx_early_return", func(t *testing.T) {
		k1 := randomTapKey(t)
		arkPsbt := arkTxPsbtB64(t, [][]byte{p2trScriptBytes(t, k1)})
		ckptPsbt := checkpointPsbtB64(t, p2trScriptBytes(t, randomTapKey(t)))

		offchainTx := newAcceptedOffchainTx(t, "ark_txid_2", arkPsbt,
			map[string]string{"ckpt_2": ckptPsbt})

		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rm.On("Vtxos").Return(vtxos)

		svc := &service{
			repoManager:         rm,
			scanner:             scn,
			transactionEventsCh: make(chan TransactionEvent, 64),
			indexerTxEventsCh:   make(chan TransactionEvent, 64),
			wg:                  &sync.WaitGroup{},
			offchainTxMu:        &sync.Mutex{},
		}
		svc.registerEventHandlers()
		rm.offchainTxHandler(offchainTx)

		require.Empty(t, scn.Watched())
		vtxos.AssertNumberOfCalls(t, "GetVtxos", 0)
		scn.AssertNumberOfCalls(t, "WatchScripts", 0)
	})

	t.Run("bad_checkpoint_psbt_decode_err", func(t *testing.T) {
		k1 := randomTapKey(t)
		arkPsbt := arkTxPsbtB64(t, [][]byte{p2trScriptBytes(t, k1)})

		offchainTx := newFinalizedOffchainTx(t, "ark_txid_3", arkPsbt,
			map[string]string{"ckpt_3": "not-a-psbt"})

		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		scn := &mockedScanner{}

		rm.On("Vtxos").Return(vtxos)

		svc := &service{
			repoManager:         rm,
			scanner:             scn,
			transactionEventsCh: make(chan TransactionEvent, 64),
			indexerTxEventsCh:   make(chan TransactionEvent, 64),
			wg:                  &sync.WaitGroup{},
			offchainTxMu:        &sync.Mutex{},
		}
		svc.registerEventHandlers()
		rm.offchainTxHandler(offchainTx)

		require.Empty(t, scn.Watched())
		vtxos.AssertNumberOfCalls(t, "GetVtxos", 0)
		scn.AssertNumberOfCalls(t, "WatchScripts", 0)
	})
}
