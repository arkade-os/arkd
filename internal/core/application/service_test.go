package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/domain/batchtrigger"
	"github.com/arkade-os/arkd/internal/core/ports"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testDust uint64 = 546

func TestStopWithPendingEventPropagation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rounds := &mockedRoundRepo{}
		rounds.On("GetSweepableRounds", mock.Anything).Return(nil, nil)
		repos := &mockedRepoManager{}
		repos.On("Rounds").Return(rounds)
		repos.On("Close").Return()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		svc := &service{
			repoManager: repos,
			wallet:      &mockWalletService{},
			sweeper:     &sweeper{scheduler: &mockScheduler{}},
			eventsCh:    make(chan []domain.Event, 64),
			ctx:         ctx,
			stop:        cancel,
			wg:          &sync.WaitGroup{},
		}
		svc.registerEventHandlers()

		// A full buffer parks the untracked propagateEvents goroutine on its send,
		// even though the registered callback has already returned.
		for range cap(svc.eventsCh) {
			svc.eventsCh <- nil
		}
		round := domain.NewRound()
		events, err := round.StartRegistration()
		require.NoError(t, err)
		repos.batchHandler(*round)
		synctest.Wait()

		svc.Stop()
		synctest.Wait() // Closing eventsCh would panic in the pending sender here.

		for range cap(svc.eventsCh) {
			<-svc.eventsCh
		}
		require.Equal(t, events, <-svc.eventsCh)
		repos.AssertExpectations(t)
	})
}

func TestEstimateIntentFeeRejectsNegativeBoardingAmount(t *testing.T) {
	message := intent.EstimateIntentFeeMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeEstimateFee},
	}
	encodedMessage, err := message.Encode()
	require.NoError(t, err)
	proof := testNoteIntentProof(
		t, encodedMessage, wire.NewTxOut(0, []byte{txscript.OP_RETURN}),
	)
	proof.Inputs[1].WitnessUtxo.Value = -1
	boardingOutpoint := proof.UnsignedTx.TxIn[1].PreviousOutPoint

	ctx := t.Context()
	vtxos := &mockedVtxoRepo{}
	vtxos.On("GetVtxos", ctx, []domain.Outpoint{{
		Txid: boardingOutpoint.Hash.String(), VOut: boardingOutpoint.Index,
	}}).Return(nil, nil)
	repos := &mockedRepoManager{}
	repos.On("Vtxos").Return(vtxos)

	svc := &service{
		repoManager: repos,
		cache: testLiveStore{settings: testSettingsStore{settings: &ports.Settings{
			SignerPubkey: testPubkey(t),
		}}},
	}
	_, appErr := svc.EstimateIntentFee(ctx, *proof, message)
	require.ErrorContains(t, appErr, "invalid amount for input 1: -1")
}

func TestNextScheduledSession(t *testing.T) {
	scheduledSessionStartTime := parseTime(t, "2023-10-10 13:00:00")
	scheduledSessionEndTime := parseTime(t, "2023-10-10 14:00:00")
	period := 1 * time.Hour

	testCases := []struct {
		now           time.Time
		expectedStart time.Time
		expectedEnd   time.Time
		description   string
	}{
		{
			now:           parseTime(t, "2023-10-10 13:00:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is exactly scheduled session start time",
		},
		{
			now:           parseTime(t, "2023-10-10 13:55:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is in the first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 14:00:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is exactly scheduled session end time",
		},
		{
			now:           parseTime(t, "2023-10-10 14:06:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is after first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 15:30:00"),
			expectedStart: parseTime(t, "2023-10-10 15:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 16:00:00"),
			description:   "now is after second scheduled session",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			startTime, endTime := calcNextScheduledSession(
				tc.now, scheduledSessionStartTime, scheduledSessionEndTime, period,
			)
			require.True(t, startTime.Equal(tc.expectedStart))
			require.True(t, endTime.Equal(tc.expectedEnd))
		})
	}
}

func TestResolveMinAmounts(t *testing.T) {
	const dust int64 = 330

	testCases := []struct {
		description     string
		vtxoMinAmount   int64
		utxoMinAmount   int64
		expectedVtxoMin int64
		expectedUtxoMin int64
	}{
		{
			description:     "sub-dust vtxo min is preserved for offchain",
			vtxoMinAmount:   1,
			utxoMinAmount:   100,
			expectedVtxoMin: 1,
			expectedUtxoMin: dust,
		},
		{
			description:     "default -1 is defaulted to dust",
			vtxoMinAmount:   -1,
			utxoMinAmount:   -1,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "arbitrary negative values are defaulted to dust",
			vtxoMinAmount:   -99,
			utxoMinAmount:   -50,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "above dust are kept as-is",
			vtxoMinAmount:   1000,
			utxoMinAmount:   2000,
			expectedVtxoMin: 1000,
			expectedUtxoMin: 2000,
		},
		{
			description:     "exactly dust are kept as-is",
			vtxoMinAmount:   dust,
			utxoMinAmount:   dust,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "zero vtxo min is preserved for offchain",
			vtxoMinAmount:   0,
			utxoMinAmount:   0,
			expectedVtxoMin: 0,
			expectedUtxoMin: dust,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			vtxoMin, utxoMin := resolveMinAmounts(
				tc.vtxoMinAmount, tc.utxoMinAmount, dust,
			)
			require.Equal(t, tc.expectedVtxoMin, vtxoMin)
			require.Equal(t, tc.expectedUtxoMin, utxoMin)
		})
	}
}

func TestValidateOffchainTxOutputs(t *testing.T) {
	anchor := txutils.AnchorOutput()
	// anchorWithValue is the anchor carrying a fee, which the CPFP child spends.
	anchorWithValue := func(value int64) *wire.TxOut {
		return &wire.TxOut{Value: value, PkScript: txutils.ANCHOR_PKSCRIPT}
	}
	malformedExtension, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_RETURN).
		AddData(extension.ArkadeMagic).
		Script()
	require.NoError(t, err)
	nonTaprootScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(make([]byte, 20)).
		Script()
	require.NoError(t, err)
	const noMaxAmount = int64(-1)
	const defaultMaxOpReturnOutputs = int64(3)

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name                    string
			txOuts                  []*wire.TxOut
			vtxoMaxAmount           int64
			vtxoMinOffchainTxAmount int64
			expectedOutputs         int
		}{
			{
				name: "anchor and regular output",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name:            "anchor only",
				txOuts:          []*wire.TxOut{anchor},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 0,
			},
			{
				name: "anchor with value below dust",
				txOuts: []*wire.TxOut{
					anchorWithValue(int64(testDust) - 1),
					{Value: 1000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "anchor with value above dust but below min offchain tx amount",
				txOuts: []*wire.TxOut{
					anchorWithValue(int64(testDust) + 100),
					{Value: 5000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:           noMaxAmount,
				vtxoMinOffchainTxAmount: int64(testDust) + 1000,
				expectedOutputs:         1,
			},
			{
				name: "subdust OP_RETURN below dust",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 100, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "subdust OP_RETURN with zero value",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "subdust OP_RETURN with value equal to dust-1",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: int64(testDust) - 1, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "subdust output is not subject to max amount check",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 100, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:   50,
				expectedOutputs: 1,
			},
			{
				name: "bare OP_RETURN with zero value",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "OP_RETURN opcode only with zero value",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: []byte{txscript.OP_RETURN}},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "extension OP_RETURN with zero value",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: testExtensionScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "exactly the maximum number of OP_RETURN outputs",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: bareOpReturn(t)},
					{Value: 0, PkScript: bareOpReturn(t)},
					{Value: 0, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 3,
			},
			{
				name: "subdust output with value equal to min offchain tx amount",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 100, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:           noMaxAmount,
				vtxoMinOffchainTxAmount: 100,
				expectedOutputs:         1,
			},
			{
				name: "zero-value OP_RETURN outputs are not subject to min amount check",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: bareOpReturn(t)},
					{Value: 0, PkScript: testExtensionScript(t)},
				},
				vtxoMaxAmount:           noMaxAmount,
				vtxoMinOffchainTxAmount: 1000,
				expectedOutputs:         2,
			},
			{
				name: "regular output with value equal to max amount",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   1000,
				expectedOutputs: 1,
			},
			{
				name: "regular output with value equal to min offchain tx amount",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:           noMaxAmount,
				vtxoMinOffchainTxAmount: 1000,
				expectedOutputs:         1,
			},
			{
				name: "regular output with value equal to dust",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: int64(testDust), PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 1,
			},
			{
				name: "multiple regular outputs",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: testP2TRScript(t)},
					{Value: 2000, PkScript: testP2TRScript(t)},
					{Value: 3000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 3,
			},
			{
				name: "regular output and subdust OP_RETURN",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: testP2TRScript(t)},
					{Value: 100, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 2,
			},
			{
				name: "regular output and bare OP_RETURN with zero value",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: testP2TRScript(t)},
					{Value: 0, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedOutputs: 2,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				outputs, _, err := validateOffchainTxOutputs(
					tt.txOuts, testDust, tt.vtxoMaxAmount, tt.vtxoMinOffchainTxAmount,
					defaultMaxOpReturnOutputs, "signed-tx-hex", "test-txid",
				)
				require.Nil(t, err)
				require.Len(t, outputs, tt.expectedOutputs)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name                    string
			txOuts                  []*wire.TxOut
			vtxoMaxAmount           int64
			vtxoMinOffchainTxAmount int64
			maxOpReturnOutputs      int64
			expectedErrCode         uint16
			expectedErr             string
			// expectedAmount is the Amount in AmountTooLowMetadata, checked when set.
			expectedAmount int
		}{
			{
				name:            "empty outputs",
				txOuts:          []*wire.TxOut{},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "missing anchor",
			},
			{
				name: "missing anchor",
				txOuts: []*wire.TxOut{
					{Value: 1000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "missing anchor",
			},
			{
				name:            "multiple anchors",
				txOuts:          []*wire.TxOut{anchor, anchor},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "multiple anchor",
			},
			{
				name: "anchor with value equal to dust",
				txOuts: []*wire.TxOut{
					anchorWithValue(int64(testDust)),
					{Value: 1000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "invalid anchor output amount",
			},
			{
				name: "anchor with value above dust",
				txOuts: []*wire.TxOut{
					anchorWithValue(10000),
					{Value: 1000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "invalid anchor output amount",
			},
			{
				name: "anchor with value equal to min offchain tx amount above dust",
				txOuts: []*wire.TxOut{
					anchorWithValue(int64(testDust) + 1000),
					{Value: 5000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:           noMaxAmount,
				vtxoMinOffchainTxAmount: int64(testDust) + 1000,
				expectedErrCode:         errors.MALFORMED_ARK_TX.Code,
				expectedErr:             "invalid anchor output amount",
			},
			{
				name: "subdust OP_RETURN with value equal to dust",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: int64(testDust), PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "subdust OP_RETURN output",
			},
			{
				name: "subdust OP_RETURN with value above dust",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 10000, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "subdust OP_RETURN output",
			},
			{
				name: "subdust output below min offchain tx amount",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 100, PkScript: testSubdustScript(t)},
				},
				vtxoMaxAmount:           noMaxAmount,
				vtxoMinOffchainTxAmount: 1000,
				expectedErrCode:         errors.AMOUNT_TOO_LOW.Code,
				expectedErr:             "lower than min vtxo amount",
				expectedAmount:          100,
			},
			{
				name: "bare OP_RETURN with non-zero value",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "not a subdust output",
			},
			{
				name: "bare OP_RETURN with value equal to 1",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "not a subdust output",
			},
			{
				name: "extension OP_RETURN with non-zero value",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1000, PkScript: testExtensionScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "extension OP_RETURN output",
			},
			{
				name: "extension OP_RETURN with value equal to 1",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 1, PkScript: testExtensionScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "extension OP_RETURN output",
			},
			{
				name: "multiple extension outputs",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: testExtensionScript(t)},
					{Value: 0, PkScript: testExtensionScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "multiple extension outputs",
			},
			{
				name: "malformed extension output",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: malformedExtension},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "malformed extension output",
			},
			{
				name: "more OP_RETURN outputs than allowed",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: bareOpReturn(t)},
					{Value: 0, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:      noMaxAmount,
				maxOpReturnOutputs: 1,
				expectedErrCode:    errors.MALFORMED_ARK_TX.Code,
				expectedErr:        "OP_RETURN outputs, max",
			},
			{
				name: "subdust OP_RETURN and bare OP_RETURN count towards the OP_RETURN limit",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 100, PkScript: testSubdustScript(t)},
					{Value: 0, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:      noMaxAmount,
				maxOpReturnOutputs: 1,
				expectedErrCode:    errors.MALFORMED_ARK_TX.Code,
				expectedErr:        "OP_RETURN outputs, max",
			},
			{
				name: "extension OP_RETURN counts towards the OP_RETURN limit",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 0, PkScript: testExtensionScript(t)},
					{Value: 0, PkScript: bareOpReturn(t)},
				},
				vtxoMaxAmount:      noMaxAmount,
				maxOpReturnOutputs: 1,
				expectedErrCode:    errors.MALFORMED_ARK_TX.Code,
				expectedErr:        "OP_RETURN outputs, max",
			},
			{
				name: "regular output above max amount",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 5000, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   1000,
				expectedErrCode: errors.AMOUNT_TOO_HIGH.Code,
				expectedErr:     "higher than max vtxo amount",
			},
			{
				name: "regular output below min offchain tx amount",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 600, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:           noMaxAmount,
				vtxoMinOffchainTxAmount: 1000,
				expectedErrCode:         errors.AMOUNT_TOO_LOW.Code,
				expectedErr:             "lower than min vtxo amount",
				expectedAmount:          600,
			},
			{
				name: "regular output below dust",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: 100, PkScript: testP2TRScript(t)},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.AMOUNT_TOO_LOW.Code,
				expectedErr:     "below dust limit",
			},
			{
				name: "regular output with non-taproot script",
				txOuts: []*wire.TxOut{
					anchor,
					{Value: int64(testDust), PkScript: nonTaprootScript},
				},
				vtxoMaxAmount:   noMaxAmount,
				expectedErrCode: errors.MALFORMED_ARK_TX.Code,
				expectedErr:     "not a taproot pkscript",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				maxOpReturnOutputs := tt.maxOpReturnOutputs
				if maxOpReturnOutputs == 0 {
					maxOpReturnOutputs = defaultMaxOpReturnOutputs
				}
				outputs, _, err := validateOffchainTxOutputs(
					tt.txOuts, testDust, tt.vtxoMaxAmount, tt.vtxoMinOffchainTxAmount,
					maxOpReturnOutputs, "signed-tx-hex", "test-txid",
				)
				require.NotNil(t, err)
				require.Equal(t, tt.expectedErrCode, err.Code())
				require.Contains(t, err.Error(), tt.expectedErr)
				if tt.expectedAmount != 0 {
					require.Equal(
						t, fmt.Sprintf("%d", tt.expectedAmount), err.Metadata()["amount"],
					)
				}
				require.Nil(t, outputs)
			})
		}
	})
}

// TestCollectTriggerContext ensures collectTriggerContext returns the correct context for batch
// trigger based on the info stored in the cache.
func TestCollectTriggerContext(t *testing.T) {
	tests := []struct {
		name        string
		intents     []ports.TimedIntent
		feeRate     uint64
		lastBatchAt time.Time
		want        batchtrigger.Context
	}{
		{
			name:    "empty intents",
			intents: nil,
			want:    batchtrigger.Context{},
		},
		{
			name: "single intent with boarding inputs and positive fee",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs: []domain.Vtxo{
							{Amount: 1000},
							{Amount: 500},
						},
						Receivers: []domain.Receiver{
							{Amount: 800},
							{Amount: 600},
						},
					},
					BoardingInputs: []ports.BoardingInput{
						{Amount: 200},
						{Amount: 300},
					},
				},
			},
			want: batchtrigger.Context{
				IntentsCount:        1,
				BoardingInputsCount: 2,
				TotalBoardingAmount: 500,
				// inputs: 1500 vtxo + 500 boarding = 2000; outputs: 1400; fee = 600
				TotalIntentFees: 600,
			},
		},
		{
			name: "intent with no boarding and no fee (inputs == outputs)",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 1000}},
						Receivers: []domain.Receiver{{Amount: 1000}},
					},
				},
			},
			want: batchtrigger.Context{IntentsCount: 1},
		},
		{
			name: "intent where outputs exceed inputs is treated as zero fee",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 100}},
						Receivers: []domain.Receiver{{Amount: 200}},
					},
				},
			},
			want: batchtrigger.Context{IntentsCount: 1},
		},
		{
			name: "multiple intents are summed",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 1000}},
						Receivers: []domain.Receiver{{Amount: 900}},
					},
					BoardingInputs: []ports.BoardingInput{{Amount: 50}},
				},
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 2000}},
						Receivers: []domain.Receiver{{Amount: 1800}},
					},
					BoardingInputs: []ports.BoardingInput{
						{Amount: 100},
						{Amount: 100},
					},
				},
			},
			want: batchtrigger.Context{
				IntentsCount:        2,
				BoardingInputsCount: 3,
				TotalBoardingAmount: 250,
				// intent 1: 1000+50 - 900 = 150
				// intent 2: 2000+200 - 1800 = 400
				TotalIntentFees: 550,
			},
		},
		{
			name: "current fee rate is captured from the wallet",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 1000}},
						Receivers: []domain.Receiver{{Amount: 1000}},
					},
				},
			},
			feeRate: 42,
			want: batchtrigger.Context{
				IntentsCount:   1,
				CurrentFeerate: 42,
			},
		},
		{
			name:        "time since last batch",
			lastBatchAt: time.Now().Add(-10 * time.Minute),
			want: batchtrigger.Context{
				TimeSinceLastBatch: 600,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &service{
				wallet: testWallet{feeRate: tt.feeRate},
				cache:  testLiveStore{intents: testIntentStore{intents: tt.intents}},
			}

			got := s.collectTriggerContext(t.Context(), tt.lastBatchAt)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestRegisterIntent(t *testing.T) {
	t.Run("registration of a vtxo that unrolls", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			unrolled bool
			conflict string
		}{
			{name: "offchain input without a conflicting spend"},
			{name: "unrolled input without a conflicting spend", unrolled: true},
			{name: "cosign pending during validation", conflict: "pending"},
			{name: "cosign recorded during validation", conflict: "recorded"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newCosignFixture(t)
				reg := f.registration(t)
				tx := f.cosignTx(t)
				vtxo := f.vtxo()
				vtxo.Unrolled = tc.unrolled
				transitioned := false
				outpoints := []domain.Outpoint{f.utxo}
				f.vtxos.ExpectedCalls = nil
				read := f.vtxos.On("GetVtxos", mock.Anything, outpoints)
				read.Run(func(mock.Arguments) {
					// Return the eligibility snapshot, but expose the unroll and
					// competing cosign to any subsequent checks.
					snapshot := vtxo
					if tc.conflict != "" && !transitioned {
						transitioned = true
						vtxo.Unrolled = true
						if tc.conflict == "pending" {
							require.NoError(t, f.svc.cache.CosignedUtxos().AddUtxos(t.Context(), outpoints))
						} else {
							require.NoError(t, f.utxos.AddUtxos(t.Context(), []domain.Utxo{{
								Outpoint: f.utxo, Amount: f.amount, PubKey: vtxo.PubKey,
								Spend: domain.UtxoSpend{Txid: tx.txid},
							}}, tx.b64))
						}
					}
					read.Return([]domain.Vtxo{snapshot}, nil)
				})

				id, appErr := f.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
				claimed, err := f.svc.cache.Intents().IncludesAny(t.Context(), outpoints)
				require.NoError(t, err)
				f.vtxos.AssertExpectations(t)
				if tc.conflict == "" {
					require.NoError(t, appErr)
					require.NotEmpty(t, id)
					require.Equal(t, outpoints, claimed)
					return
				}

				require.True(t, transitioned, "the conflicting spend must have landed")
				require.Empty(t, claimed, "an intent from a stale read must not be pushed")
				require.Empty(t, id)
				require.Error(t, appErr)
				require.Equal(t, errors.VTXO_ALREADY_SPENT.Code, appErr.Code())
				require.Contains(t, appErr.Error(), "cosigned")
				require.Contains(t, appErr.Metadata()["vtxo_outpoints"], f.utxo.String())
			})
		}
	})

	// the receiver pubkey of an offchain output is read by slicing the pkscript
	// at [2:], non-taproot scripts must be rejected before that.
	t.Run("reject non-taproot offchain output", func(t *testing.T) {
		p2wpkhScript, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(make([]byte, 20)).
			Script()
		require.NoError(t, err)

		tests := []struct {
			description string
			pkScript    []byte
		}{
			{"script shorter than 2 bytes", []byte{txscript.OP_TRUE}},
			{"p2wpkh script", p2wpkhScript},
		}

		for _, tt := range tests {
			t.Run(tt.description, func(t *testing.T) {
				ctx := t.Context()
				message := intent.RegisterMessage{
					BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
				}
				encodedMessage, err := message.Encode()
				require.NoError(t, err)

				proof := testNoteIntentProof(t, encodedMessage, &wire.TxOut{
					Value: int64(testDust) * 2, PkScript: tt.pkScript,
				})

				vtxos := &mockedVtxoRepo{}
				vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(nil, nil)
				repos := &mockedRepoManager{}
				repos.On("Vtxos").Return(vtxos)

				svc := newRegisterIntentTestService(t, repos)

				_, appErr := svc.RegisterIntent(ctx, *proof, message)
				require.Error(t, appErr)
				require.Equal(t, errors.INVALID_PKSCRIPT.Code, appErr.Code())
			})
		}
	})

	t.Run("reject invalid cosigner keys and the operator key in any encoding", func(t *testing.T) {
		operatorPubkey := testPubkey(t)
		flippedParity := operatorPubkey.SerializeCompressed()
		flippedParity[0] ^= 1

		tests := []struct {
			description string
			cosigner    string
			expectedErr string
		}{
			{
				"compressed",
				hex.EncodeToString(operatorPubkey.SerializeCompressed()), "is used by us",
			},
			{"compressed with flipped parity", hex.EncodeToString(flippedParity), "is used by us"},
			{
				"uncompressed",
				hex.EncodeToString(operatorPubkey.SerializeUncompressed()), "is used by us",
			},
			{"not a pubkey", "zzzz", "invalid cosigner pubkey"},
		}

		for _, tt := range tests {
			t.Run(tt.description, func(t *testing.T) {
				message := intent.RegisterMessage{
					BaseMessage:         intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
					CosignersPublicKeys: []string{tt.cosigner},
				}
				encodedMessage, err := message.Encode()
				require.NoError(t, err)

				receiverScript, err := script.P2TRScript(testPubkey(t))
				require.NoError(t, err)
				proof := testNoteIntentProof(t, encodedMessage, &wire.TxOut{
					Value: int64(testDust) * 2, PkScript: receiverScript,
				})

				vtxos := &mockedVtxoRepo{}
				vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(nil, nil)
				repos := &mockedRepoManager{}
				repos.On("Vtxos").Return(vtxos)

				svc := newRegisterIntentTestService(t, repos)
				svc.operatorPubkey = operatorPubkey

				_, appErr := svc.RegisterIntent(t.Context(), *proof, message)
				require.Error(t, appErr)
				require.Equal(t, errors.INVALID_INTENT_MESSAGE.Code, appErr.Code())
				require.ErrorContains(t, appErr, tt.expectedErr)
			})
		}
	})
}

func TestSubmitOffchainTx(t *testing.T) {
	// The control block of a checkpoint input ends up in the checkpoint we sign. The merkle root
	// doesn't commit to its internal key, so a foreign one would pass every other check while
	// consensus rejects the witness: it's refused before anything is signed or recorded.
	t.Run("checkpoint control block with foreign internal key", func(t *testing.T) {
		tx := newTestOneShotTx(t, 1)
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx.checkpointTxs[0]), true)
		require.NoError(t, err)
		foreignKey := schnorr.SerializePubKey(testPubkey(t))
		copy(ptx.Inputs[0].TaprootLeafScript[0].ControlBlock[1:33], foreignKey)
		checkpoint, err := ptx.B64Encode()
		require.NoError(t, err)

		resp, appErr := tx.svc.SubmitOffchainTx(t.Context(), []string{checkpoint}, tx.arkTx)
		require.Error(t, appErr)
		require.Nil(t, resp)
		require.Equal(t, errors.INVALID_PSBT_INPUT.Code, appErr.Code())
		require.Contains(t, appErr.Error(), "invalid control block")
		// The request is recorded as failed, like any rejected two-step submission, but never
		// accepted: nothing is signed for it nor cached.
		for _, call := range tx.events.Calls {
			for _, event := range call.Arguments.Get(3).([]domain.Event) {
				require.NotEqual(t, domain.EventTypeOffchainTxAccepted, event.GetType())
			}
		}
		require.Empty(t, tx.offchainTxs.added)
	})

	t.Run("an input is checked for bans by its stored script", func(t *testing.T) {
		spend := testOffchainTxSpendingVtxo(t)
		svc := testSubmitOffchainTxService(t, spend.vtxo, convictionRepoStub{
			convictions: map[string][]domain.ScriptConviction{spend.vtxoScript: {{}}},
		})

		_, appErr := svc.SubmitOffchainTx(
			t.Context(), []string{spend.checkpointTx}, spend.arkTx,
		)
		require.Error(t, appErr)
		require.Equal(t, errors.VTXO_BANNED.Code, appErr.Code())
		require.Equal(t, spend.vtxo.Outpoint.String(), appErr.Metadata()["vtxo_outpoint"])
		require.Equal(t, "["+spend.vtxoScript+"]", appErr.Metadata()["scripts"])
	})

	t.Run("a failed ban lookup reports the tx and its inputs", func(t *testing.T) {
		spend := testOffchainTxSpendingVtxo(t)
		svc := testSubmitOffchainTxService(t, spend.vtxo, convictionRepoStub{
			err: fmt.Errorf("convictions unavailable"),
		})

		_, appErr := svc.SubmitOffchainTx(
			t.Context(), []string{spend.checkpointTx}, spend.arkTx,
		)
		require.Error(t, appErr)
		require.Equal(t, errors.INTERNAL_ERROR.Code, appErr.Code())
		require.Equal(t, spend.arkTxid, appErr.Metadata()["txid"])
		require.Contains(t, appErr.Metadata()["vtxos"], spend.vtxo.Outpoint.Txid)
	})

	// A tx submitted with the checkpoints already signed by the owner is finalized in the same
	// call, so no second step is needed.
	t.Run("one shot", func(t *testing.T) {
		expectedEvents := []domain.EventType{
			domain.EventTypeOffchainTxRequested,
			domain.EventTypeOffchainTxAccepted,
			domain.EventTypeOffchainTxFinalized,
		}
		savedEvents := func(t *testing.T, events *mockedEventRepo) []domain.EventType {
			t.Helper()
			events.AssertNumberOfCalls(t, "Save", 1)
			saved := events.Calls[0].Arguments.Get(3).([]domain.Event)
			types := make([]domain.EventType, 0, len(saved))
			for _, event := range saved {
				types = append(types, event.GetType())
			}
			return types
		}
		requireFinalized := func(t *testing.T, tx testOneShotTx, resp *AcceptedOffchainTx) {
			t.Helper()
			require.Equal(t, tx.arkTxid, resp.TxId)
			require.Len(t, resp.SignedCheckpointTxs, len(tx.checkpointTxs))
			// The checkpoints are returned fully signed: owner and server.
			for _, checkpoint := range resp.SignedCheckpointTxs {
				valid, _, err := tx.svc.builder.VerifyVtxoTapscriptSigs(checkpoint, true)
				require.NoError(t, err)
				require.True(t, valid)
			}
			require.Equal(t, expectedEvents, savedEvents(t, tx.events))
			require.Equal(t, []string{tx.arkTxid}, tx.offchainTxs.added)
		}

		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name      string
				numInputs int
			}{
				{
					name:      "single input",
					numInputs: 1,
				},
				{
					name:      "multiple inputs",
					numInputs: 3,
				},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tx := newTestOneShotTx(t, tt.numInputs)

					resp, appErr := tx.svc.SubmitOffchainTx(
						t.Context(), tx.signedCheckpoints, tx.arkTx,
					)
					require.NoError(t, appErr)
					requireFinalized(t, tx, resp)
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name      string
				numInputs int
				// invalidate tampers with the signed checkpoints, given the unsigned ones too.
				invalidate func(t *testing.T, signed, unsigned []string)
			}{
				{
					name:      "invalid checkpoint signature",
					numInputs: 1,
					invalidate: func(t *testing.T, signed, _ []string) {
						ptx, err := psbt.NewFromRawBytes(strings.NewReader(signed[0]), true)
						require.NoError(t, err)
						ptx.Inputs[0].TaprootScriptSpendSig[0].Signature[0] ^= 1
						signed[0], err = ptx.B64Encode()
						require.NoError(t, err)
					},
				},
				{
					name:      "partially signed checkpoints",
					numInputs: 3,
					invalidate: func(_ *testing.T, signed, unsigned []string) {
						// Only the first checkpoint retains its signature.
						copy(signed[1:], unsigned[1:])
					},
				},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tx := newTestOneShotTx(t, tt.numInputs)
					invalidCheckpoints := append([]string(nil), tx.signedCheckpoints...)
					tt.invalidate(t, invalidCheckpoints, tx.checkpointTxs)

					resp, appErr := tx.svc.SubmitOffchainTx(
						t.Context(), invalidCheckpoints, tx.arkTx,
					)
					require.Error(t, appErr)
					require.Equal(t, errors.INVALID_SIGNATURE.Code, appErr.Code())
					require.Contains(t, appErr.Error(), "invalid signature in checkpoint tx")
					require.Nil(t, resp)
					// The rejection leaves no trace, so the tx can be submitted again.
					tx.events.AssertNotCalled(
						t, "Save", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
					)
					require.Empty(t, tx.offchainTxs.added)

					resp, appErr = tx.svc.SubmitOffchainTx(
						t.Context(), tx.signedCheckpoints, tx.arkTx,
					)
					require.NoError(t, appErr)
					requireFinalized(t, tx, resp)
				})
			}
		})

		// A one shot client still calls finalize, be the tx served by the cache or by the db.
		t.Run("finalize again", func(t *testing.T) {
			for _, servedBy := range []string{"cache", "db"} {
				t.Run(servedBy, func(t *testing.T) {
					tx := newTestOneShotTx(t, 2)

					resp, err := tx.svc.SubmitOffchainTx(
						t.Context(), tx.signedCheckpoints, tx.arkTx,
					)
					require.NoError(t, err)
					requireFinalized(t, tx, resp)

					if servedBy == "db" {
						tx.offchainTxRepo.tx = tx.offchainTxs.cached
						require.NoError(t, tx.offchainTxs.Remove(t.Context(), tx.arkTxid))
					}

					// The tx is finalized, a valid request is "ignored" and no error is returned.
					err = tx.svc.FinalizeOffchainTx(
						t.Context(), tx.arkTxid, resp.SignedCheckpointTxs,
					)
					require.NoError(t, err)
				})
			}
		})
	})
}

func TestMarkSweptBatches(t *testing.T) {
	errUnavailable := fmt.Errorf("unavailable")

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name          string
			fixture       testSweptBatchFixture
			expectedSwept bool
		}{
			{
				name:          "swept batch",
				fixture:       testSweptBatchFixture{spent: true},
				expectedSwept: true,
			},
			{
				name:          "unspent batch output",
				fixture:       testSweptBatchFixture{},
				expectedSwept: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				batch := testSweptBatchService(t, tt.fixture)

				batch.svc.markSweptBatches(t.Context())

				batch.rounds.AssertNotCalled(t, "GetRoundVtxoTree", mock.Anything, mock.Anything)
				batch.wallet.AssertNotCalled(t, "GetTransaction", mock.Anything, mock.Anything)
				if !tt.expectedSwept {
					batch.rounds.AssertNotCalled(t, "SweepRounds", mock.Anything, mock.Anything)
					return
				}
				batch.rounds.AssertCalled(
					t, "SweepRounds", mock.Anything, []string{batch.round.CommitmentTxid},
				)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name          string
			fixture       testSweptBatchFixture
			expectedSweep bool
		}{
			{
				name:          "failed to get expired batches",
				fixture:       testSweptBatchFixture{spent: true, expiredErr: errUnavailable},
				expectedSweep: false,
			},
			{
				name:          "failed to get batch output status",
				fixture:       testSweptBatchFixture{spent: true, spentErr: errUnavailable},
				expectedSweep: false,
			},
			{
				name:          "failed to mark batches as swept",
				fixture:       testSweptBatchFixture{spent: true, sweepErr: errUnavailable},
				expectedSweep: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				batch := testSweptBatchService(t, tt.fixture)

				batch.svc.markSweptBatches(t.Context())

				if !tt.expectedSweep {
					batch.rounds.AssertNotCalled(t, "SweepRounds", mock.Anything, mock.Anything)
					return
				}
				batch.rounds.AssertCalled(
					t, "SweepRounds", mock.Anything, []string{batch.round.CommitmentTxid},
				)
			})
		}
	})
}

func TestIsBatchSwept(t *testing.T) {
	errUnavailable := fmt.Errorf("unavailable")
	errRootNotFound := fmt.Errorf("rpc error: code = Unknown desc = transaction not found")

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name             string
			withCheckUnroll  bool
			fixture          testSweptBatchFixture
			expectedSwept    bool
			expectedRootRead bool
		}{
			{
				name:             "swept batch without unroll check",
				fixture:          testSweptBatchFixture{spent: true, rootTxErr: errRootNotFound},
				expectedSwept:    true,
				expectedRootRead: false,
			},
			{
				name:             "unswept batch without unroll check",
				fixture:          testSweptBatchFixture{rootTxErr: errRootNotFound},
				expectedSwept:    false,
				expectedRootRead: false,
			},
			{
				name:             "swept batch with unroll check",
				withCheckUnroll:  true,
				fixture:          testSweptBatchFixture{spent: true, rootTxErr: errRootNotFound},
				expectedSwept:    true,
				expectedRootRead: true,
			},
			{
				name:             "unrolled batch with unroll check",
				withCheckUnroll:  true,
				fixture:          testSweptBatchFixture{spent: true, rootTx: "rootTx"},
				expectedSwept:    false,
				expectedRootRead: true,
			},
			{
				name:             "unspent batch output with unroll check",
				withCheckUnroll:  true,
				fixture:          testSweptBatchFixture{rootTxErr: errRootNotFound},
				expectedSwept:    false,
				expectedRootRead: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				batch := testSweptBatchService(t, tt.fixture)

				isSwept, err := batch.svc.isBatchSwept(
					t.Context(), batch.round.CommitmentTxid, tt.withCheckUnroll,
				)
				require.NoError(t, err)
				require.Equal(t, tt.expectedSwept, isSwept)
				if tt.expectedRootRead {
					batch.rounds.AssertCalled(
						t, "GetRoundVtxoTree", mock.Anything, batch.round.CommitmentTxid,
					)
					batch.wallet.AssertCalled(t, "GetTransaction", mock.Anything, batch.rootTxid)
					return
				}
				batch.rounds.AssertNotCalled(t, "GetRoundVtxoTree", mock.Anything, mock.Anything)
				batch.wallet.AssertNotCalled(t, "GetTransaction", mock.Anything, mock.Anything)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name            string
			withCheckUnroll bool
			fixture         testSweptBatchFixture
		}{
			{
				name:    "failed to get batch output status without unroll check",
				fixture: testSweptBatchFixture{spent: true, spentErr: errUnavailable},
			},
			{
				name:            "failed to get batch output status with unroll check",
				withCheckUnroll: true,
				fixture:         testSweptBatchFixture{spent: true, spentErr: errUnavailable},
			},
			{
				name:            "failed to get vtxo tree with unroll check",
				withCheckUnroll: true,
				fixture:         testSweptBatchFixture{spent: true, vtxoTreeErr: errUnavailable},
			},
			{
				name:            "failed to get root tx with unroll check",
				withCheckUnroll: true,
				fixture:         testSweptBatchFixture{spent: true, rootTxErr: errUnavailable},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				batch := testSweptBatchService(t, tt.fixture)

				isSwept, err := batch.svc.isBatchSwept(
					t.Context(), batch.round.CommitmentTxid, tt.withCheckUnroll,
				)
				require.ErrorIs(t, err, errUnavailable)
				require.False(t, isSwept)
			})
		}
	})
}

func TestRegisterCosignerNonces(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := newTestTreeSigningFixture(t)
		nonces, err := f.signer.GetNonces()
		require.NoError(t, err)

		appErr := f.svc.RegisterCosignerNonces(t.Context(), f.roundId, f.cosigner, nonces)
		require.NoError(t, appErr)
		require.Equal(t, nonces, f.store.nonces[f.cosigner])
	})

	t.Run("invalid", func(t *testing.T) {
		storeErr := fmt.Errorf("store unavailable")
		tests := []struct {
			name string
			// setup returns the pubkey and nonces to submit, after tampering with the fixture.
			setup        func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces)
			expectedCode uint16
			expectedErr  string
		}{
			{
				name: "invalid pubkey format",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces) {
					return "not-hex", f.nonces(t)
				},
				expectedCode: errors.INVALID_TREE_NONCES.Code,
				expectedErr:  "must be a hex encoded compressed public key",
			},
			{
				name: "invalid pubkey",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces) {
					return hex.EncodeToString(make([]byte, 33)), f.nonces(t)
				},
				expectedCode: errors.INVALID_TREE_NONCES.Code,
				expectedErr:  "invalid cosigner pubkey",
			},
			{
				name: "signing session not found",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces) {
					f.store.session = nil
					return f.cosigner, f.nonces(t)
				},
				expectedCode: errors.INTERNAL_ERROR.Code,
				expectedErr:  "signing session not found",
			},
			{
				// AddNonces refuses it too, but only after the tree checks and as an internal
				// error.
				name: "not a cosigner of the round",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces) {
					return hex.EncodeToString(testPubkey(t).SerializeCompressed()), f.nonces(t)
				},
				expectedCode: errors.INVALID_TREE_NONCES.Code,
				expectedErr:  "is not a cosigner",
			},
			{
				name: "missing nonces",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces) {
					return f.cosigner, tree.TreeNonces{}
				},
				expectedCode: errors.INVALID_TREE_NONCES.Code,
				expectedErr:  "missing musig2 nonce",
			},
			{
				name: "invalid nonce",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces) {
					nonces := f.nonces(t)
					for _, nonce := range nonces {
						// 0x05 is not a valid compressed point prefix. All zeros would be
						// accepted instead, as musig2 encodes the point at infinity that way.
						nonce.PubNonce[0] = 0x05
					}
					return f.cosigner, nonces
				},
				expectedCode: errors.INVALID_TREE_NONCES.Code,
				expectedErr:  "invalid musig2 nonce",
			},
			{
				name: "fail to store the nonces",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreeNonces) {
					f.store.err = storeErr
					return f.cosigner, f.nonces(t)
				},
				expectedCode: errors.INTERNAL_ERROR.Code,
				expectedErr:  "something went wrong",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newTestTreeSigningFixture(t)
				pubkey, nonces := tt.setup(t, f)

				appErr := f.svc.RegisterCosignerNonces(t.Context(), f.roundId, pubkey, nonces)
				require.Error(t, appErr)
				require.Equal(t, tt.expectedCode, appErr.Code())
				require.Contains(t, appErr.Error(), tt.expectedErr)
				require.Empty(t, f.store.nonces)
			})
		}
	})
}

func TestRegisterCosignerSignatures(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := newTestTreeSigningFixture(t)
		f.aggregateNonces(t)
		sigs, err := f.signer.Sign()
		require.NoError(t, err)

		appErr := f.svc.RegisterCosignerSignatures(t.Context(), f.roundId, f.cosigner, sigs)
		require.NoError(t, appErr)
		require.Equal(t, sigs, f.store.sigs[f.cosigner])
	})

	t.Run("invalid", func(t *testing.T) {
		storeErr := fmt.Errorf("store unavailable")
		tests := []struct {
			name string
			// setup returns the pubkey and signatures to submit, after tampering with the
			// fixture.
			setup        func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs)
			expectedCode uint16
			expectedErr  string
		}{
			{
				name: "signing session not found",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs) {
					f.store.session = nil
					return f.cosigner, f.sigs(t)
				},
				expectedCode: errors.INTERNAL_ERROR.Code,
				expectedErr:  "signing session not found",
			},
			{
				name: "not a cosigner of the round",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs) {
					return hex.EncodeToString(testPubkey(t).SerializeCompressed()), f.sigs(t)
				},
				expectedCode: errors.INVALID_SIGNATURE.Code,
				expectedErr:  "is not a cosigner",
			},
			{
				name: "submit signatures before nonces aggregation",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs) {
					return f.cosigner, tree.TreePartialSigs{}
				},
				expectedCode: errors.INVALID_SIGNATURE.Code,
				expectedErr:  "nonces not aggregated yet",
			},
			{
				name: "missing nonces",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs) {
					sigs := f.sigs(t)
					delete(f.session.Nonces, f.cosigner)
					return f.cosigner, sigs
				},
				expectedCode: errors.INVALID_SIGNATURE.Code,
				expectedErr:  "no nonces submitted",
			},
			{
				name: "tampered partial signature",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs) {
					sigs := f.sigs(t)
					for _, sig := range sigs {
						sig.S.SetInt(1)
					}
					return f.cosigner, sigs
				},
				expectedCode: errors.INVALID_SIGNATURE.Code,
				expectedErr:  "invalid tree signatures",
			},
			{
				name: "signatures of another cosigner",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs) {
					f.aggregateNonces(t)
					sigs, err := f.opSigner.Sign()
					require.NoError(t, err)
					return f.cosigner, sigs
				},
				expectedCode: errors.INVALID_SIGNATURE.Code,
				expectedErr:  "invalid tree signatures",
			},
			{
				name: "fail to store the signatures",
				setup: func(t *testing.T, f *testTreeSigningFixture) (string, tree.TreePartialSigs) {
					f.store.err = storeErr
					return f.cosigner, f.sigs(t)
				},
				expectedCode: errors.INTERNAL_ERROR.Code,
				expectedErr:  "something went wrong",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newTestTreeSigningFixture(t)
				pubkey, sigs := tt.setup(t, f)

				appErr := f.svc.RegisterCosignerSignatures(t.Context(), f.roundId, pubkey, sigs)
				require.Error(t, appErr)
				require.Equal(t, tt.expectedCode, appErr.Code())
				require.Contains(t, appErr.Error(), tt.expectedErr)
				require.Empty(t, f.store.sigs)
			})
		}
	})
}

func parseTime(t *testing.T, value string) time.Time {
	tm, err := time.ParseInLocation(time.DateTime, value, time.UTC)
	require.NoError(t, err)
	return tm
}

func testPubkey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key.PubKey()
}

func testSubdustScript(t *testing.T) []byte {
	t.Helper()
	s, err := script.SubDustScript(testPubkey(t))
	require.NoError(t, err)
	return s
}

func testP2TRScript(t *testing.T) []byte {
	t.Helper()
	s, err := script.P2TRScript(testPubkey(t))
	require.NoError(t, err)
	return s
}

// bareOpReturn builds an OP_RETURN script with arbitrary data that is neither
// a subdust script (which requires exactly 32-byte push) nor an asset packet.
func bareOpReturn(t *testing.T) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_RETURN).
		AddData([]byte("not-subdust-not-asset")).
		Script()
	require.NoError(t, err)
	return s
}

func testExtensionScript(t *testing.T) []byte {
	t.Helper()
	ext := extension.Extension{
		extension.UnknownPacket{PacketType: 0xFF, Data: []byte("test")},
	}
	s, err := ext.Serialize()
	require.NoError(t, err)
	return s
}

// testOffchainTxSpend is a stored vtxo and an unsigned ark tx spending it through
// one checkpoint tx, encoded the way SubmitOffchainTx takes them.
type testOffchainTxSpend struct {
	vtxo         domain.Vtxo
	vtxoScript   string
	arkTx        string
	arkTxid      string
	checkpointTx string
}

func testOffchainTxSpendingVtxo(t *testing.T) testOffchainTxSpend {
	t.Helper()

	var vtxoOutpoint wire.OutPoint
	_, err := rand.Read(vtxoOutpoint.Hash[:])
	require.NoError(t, err)

	owner := testPubkey(t)
	vtxoScript, err := script.P2TRScript(owner)
	require.NoError(t, err)
	vtxo := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: vtxoOutpoint.Hash.String(), VOut: vtxoOutpoint.Index},
		PubKey:   hex.EncodeToString(schnorr.SerializePubKey(owner)),
		Amount:   1000,
	}

	checkpoint, err := psbt.New(
		[]*wire.OutPoint{&vtxoOutpoint},
		[]*wire.TxOut{{Value: int64(vtxo.Amount), PkScript: []byte{txscript.OP_TRUE}}},
		3, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	checkpointTx, err := checkpoint.B64Encode()
	require.NoError(t, err)

	arkPtx, err := psbt.New(
		[]*wire.OutPoint{{Hash: checkpoint.UnsignedTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: int64(vtxo.Amount), PkScript: []byte{txscript.OP_TRUE}}},
		3, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	arkPtx.Inputs[0].WitnessUtxo = checkpoint.UnsignedTx.TxOut[0]
	arkTx, err := arkPtx.B64Encode()
	require.NoError(t, err)

	return testOffchainTxSpend{
		vtxo:         vtxo,
		vtxoScript:   hex.EncodeToString(vtxoScript),
		arkTx:        arkTx,
		arkTxid:      arkPtx.UnsignedTx.TxID(),
		checkpointTx: checkpointTx,
	}
}

// testSubmitOffchainTxService builds the service SubmitOffchainTx needs to reach
// its ban check, with banning on, vtxo stored and convictions answering.
func testSubmitOffchainTxService(
	t *testing.T, vtxo domain.Vtxo, convictions domain.ConvictionRepository,
) *service {
	t.Helper()

	offchainTxs := &mockedOffchainTxRepo{}
	offchainTxs.On("GetOffchainTx", mock.Anything, mock.Anything).Return(nil, nil)
	vtxos := &mockedVtxoRepo{}
	vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return([]domain.Vtxo{vtxo}, nil)
	repos := &mockedRepoManager{}
	repos.On("OffchainTxs").Return(offchainTxs)
	repos.On("Vtxos").Return(vtxos)
	repos.On("Convictions").Return(convictions)

	return &service{
		repoManager: repos,
		cache: testLiveStore{settings: testSettingsStore{settings: &ports.Settings{
			Settings: domain.Settings{BanThreshold: 1},
		}}},
	}
}

// testOneShotTx is an offchain tx spending stored vtxos through their forfeit closure, with
// the ark tx and the checkpoints signed by the owner, and the service to submit it to.
type testOneShotTx struct {
	svc            *service
	events         *mockedEventRepo
	offchainTxs    *testOneShotOffchainTxStore
	offchainTxRepo *testOneShotOffchainTxRepo
	arkTxid        string
	// arkTx is signed by the owner.
	arkTx string
	// checkpointTxs are unsigned, as submitted in two steps.
	checkpointTxs []string
	// signedCheckpoints are signed by the owner, as submitted in one shot.
	signedCheckpoints []string
}

// newTestOneShotTx builds a tx spending numInputs vtxos of 10,000 sats each to a single
// output, through a service whose signer and tx builder are real enough to verify and
// finalize it: the signer signs with an in-memory key and the builder is the covenantless one.
func newTestOneShotTx(t *testing.T, numInputs int) testOneShotTx {
	t.Helper()

	serverPrv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownerPrv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	exitDelay, _ := arklib.ParseRelativeLocktime(512)
	checkpointExitDelay, _ := arklib.ParseRelativeLocktime(1024)

	vtxoScript := &script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{ownerPrv.PubKey(), serverPrv.PubKey()},
		},
		&script.CSVMultisigClosure{
			Locktime:        exitDelay,
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{ownerPrv.PubKey()}},
		},
	}}
	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	forfeitScript, err := vtxoScript.Closures[0].Script()
	require.NoError(t, err)
	forfeitProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(forfeitScript).TapHash(),
	)
	require.NoError(t, err)
	ctrlBlock, err := txscript.ParseControlBlock(forfeitProof.ControlBlock)
	require.NoError(t, err)

	const amount = int64(10_000)
	now := time.Now()
	vtxos := make([]domain.Vtxo, 0, numInputs)
	ins := make([]offchain.VtxoInput, 0, numInputs)
	for range numInputs {
		outpoint := &wire.OutPoint{}
		_, err := rand.Read(outpoint.Hash[:])
		require.NoError(t, err)
		vtxos = append(vtxos, domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: outpoint.Hash.String(), VOut: 0},
			Amount:             uint64(amount),
			PubKey:             hex.EncodeToString(schnorr.SerializePubKey(tapKey)),
			CommitmentTxids:    []string{"commitment"},
			RootCommitmentTxid: "commitment",
			ExpiresAt:          now.Add(time.Hour).Unix(),
			CreatedAt:          now.Unix(),
		})
		ins = append(ins, offchain.VtxoInput{
			Outpoint: outpoint,
			Amount:   amount,
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: forfeitProof.Script,
			},
			RevealedTapscripts: tapscripts,
		})
	}

	checkpointTapscript, err := (&script.CSVMultisigClosure{
		Locktime:        checkpointExitDelay,
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPrv.PubKey()}},
	}).Script()
	require.NoError(t, err)
	arkPtx, checkpointPtxs, err := offchain.BuildTxs(
		ins, []*wire.TxOut{{Value: amount * int64(numInputs), PkScript: testP2TRScript(t)}},
		checkpointTapscript,
	)
	require.NoError(t, err)
	unsignedArkTx, err := arkPtx.B64Encode()
	require.NoError(t, err)
	checkpointTxs := make([]string, 0, numInputs)
	signedCheckpoints := make([]string, 0, numInputs)
	for _, checkpointPtx := range checkpointPtxs {
		checkpointTx, err := checkpointPtx.B64Encode()
		require.NoError(t, err)
		checkpointTxs = append(checkpointTxs, checkpointTx)
		signedCheckpoints = append(signedCheckpoints, signTapscriptInputs(t, checkpointTx, ownerPrv))
	}

	events := &mockedEventRepo{}
	events.On("Save", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	vtxoRepo := &mockedVtxoRepo{}
	vtxoRepo.On("GetVtxos", mock.Anything, mock.Anything).Return(vtxos, nil)
	offchainTxRepo := &testOneShotOffchainTxRepo{}
	repos := &mockedRepoManager{RepoManager: testOneShotRepos{events: events}}
	repos.On("Vtxos").Return(vtxoRepo)
	repos.On("OffchainTxs").Return(offchainTxRepo)
	repos.On("Convictions").Return(convictionRepoStub{})
	wallet := &mockedWallet{}
	wallet.On("GetDustAmount", mock.Anything).Return(testDust, nil)
	signer := &testTapscriptSigner{t: t, prv: serverPrv}
	offchainTxs := &testOneShotOffchainTxStore{}
	settings := &ports.Settings{
		Settings: domain.Settings{
			BanThreshold:          1,
			UnilateralExitDelay:   exitDelay,
			CheckpointExitDelay:   checkpointExitDelay,
			VtxoTreeExpiry:        exitDelay,
			VtxoMinAmount:         1,
			VtxoMaxAmount:         -1,
			MaxTxWeight:           400_000,
			MaxOpReturnOutputs:    3,
			AssetTxMaxWeightRatio: 0.5,
		},
		DustAmount:          testDust,
		SignerPubkey:        serverPrv.PubKey(),
		ForfeitPubkey:       serverPrv.PubKey(),
		CheckpointTapscript: checkpointTapscript,
	}

	return testOneShotTx{
		svc: &service{
			repoManager: repos,
			wallet:      wallet,
			signer:      signer,
			builder:     txbuilder.NewTxBuilder(wallet, signer, arklib.Bitcoin),
			cache: testLiveStore{
				settings:    testSettingsStore{settings: settings},
				offchainTxs: offchainTxs,
				intents:     testIntentStore{},
			},
			offchainTxMu: &sync.Mutex{},
		},
		events:            events,
		offchainTxs:       offchainTxs,
		offchainTxRepo:    offchainTxRepo,
		arkTxid:           arkPtx.UnsignedTx.TxID(),
		arkTx:             signTapscriptInputs(t, unsignedArkTx, ownerPrv),
		checkpointTxs:     checkpointTxs,
		signedCheckpoints: signedCheckpoints,
	}
}

// signTapscriptInputs signs with prv every input of the psbt carrying a tapscript leaf, the
// way a client or the signer does, and returns the signed psbt.
func signTapscriptInputs(t *testing.T, tx string, prv *btcec.PrivateKey) string {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	require.NoError(t, err)
	prevouts, err := txutils.GetPrevOutputFetcher(ptx)
	require.NoError(t, err)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevouts)

	for i, in := range ptx.Inputs {
		if len(in.TaprootLeafScript) == 0 {
			continue
		}
		leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
		sig, err := txscript.RawTxInTapscriptSignature(
			ptx.UnsignedTx, sigHashes, i, in.WitnessUtxo.Value, in.WitnessUtxo.PkScript,
			leaf, txscript.SigHashDefault, prv,
		)
		require.NoError(t, err)
		leafHash := leaf.TapHash()
		ptx.Inputs[i].TaprootScriptSpendSig = append(
			ptx.Inputs[i].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
				Signature:   sig[:64],
				XOnlyPubKey: schnorr.SerializePubKey(prv.PubKey()),
				LeafHash:    leafHash[:],
				SigHash:     txscript.SigHashDefault,
			},
		)
	}
	signed, err := ptx.B64Encode()
	require.NoError(t, err)
	return signed
}

// testTapscriptSigner is a ports.SignerService signing with an in-memory key, so the tx builder
// can verify and finalize what it signs.
type testTapscriptSigner struct {
	ports.SignerService
	t   *testing.T
	prv *btcec.PrivateKey
}

func (s *testTapscriptSigner) GetPubkey(context.Context) (*btcec.PublicKey, error) {
	return s.prv.PubKey(), nil
}

func (s *testTapscriptSigner) GetDeprecatedPubkeys(
	context.Context,
) ([]ports.DeprecatedSignerPubkey, error) {
	return nil, nil
}

func (s *testTapscriptSigner) SignTransactionTapscript(
	_ context.Context, tx string, _ []int,
) (string, error) {
	return signTapscriptInputs(s.t, tx, s.prv), nil
}

// testOneShotRepos backs the repos mockedRepoManager has no expectations for: the event store
// the tx is saved to, and the asset repo, which is never consulted since the tx carries no
// asset packet.
type testOneShotRepos struct {
	ports.RepoManager
	events domain.EventRepository
}

func (r testOneShotRepos) Events() domain.EventRepository { return r.events }

func (r testOneShotRepos) Assets() domain.AssetRepository { return nil }

// testOneShotOffchainTxStore is an offchain tx cache holding what is added to it and recording
// it. Like the real one it hands out copies, so what a caller does with one is not cached.
type testOneShotOffchainTxStore struct {
	ports.OffChainTxStore
	added  []string
	cached *domain.OffchainTx
}

func (s *testOneShotOffchainTxStore) Add(_ context.Context, tx domain.OffchainTx) error {
	s.added = append(s.added, tx.ArkTxid)
	s.cached = &tx
	return nil
}

func (s *testOneShotOffchainTxStore) Get(
	_ context.Context, arkTxid string,
) (*domain.OffchainTx, error) {
	if s.cached == nil || s.cached.ArkTxid != arkTxid {
		return nil, nil
	}
	cached := *s.cached
	return &cached, nil
}

func (s *testOneShotOffchainTxStore) Remove(context.Context, string) error {
	s.cached = nil
	return nil
}

func (s *testOneShotOffchainTxStore) IncludesAny(
	context.Context, []domain.Outpoint,
) ([]domain.Outpoint, error) {
	return nil, nil
}

// testOneShotOffchainTxRepo is the offchain tx db, empty until a test stores the tx in it.
type testOneShotOffchainTxRepo struct {
	domain.OffchainTxRepository
	tx *domain.OffchainTx
}

func (r *testOneShotOffchainTxRepo) GetOffchainTx(
	_ context.Context, _ string,
) (*domain.OffchainTx, error) {
	return r.tx, nil
}

// testNoteIntentProof builds an intent proof whose only ownership input is a
// note closure, ie. a hash-lock requiring the preimage instead of a signature.
func testNoteIntentProof(t *testing.T, message string, out *wire.TxOut) *intent.Proof {
	t.Helper()

	return testNotesIntentProof(t, message, out, 1)
}

// testNotesIntentProof builds an intent proof with one note closure ownership
// input per note, each holding out's value.
func testNotesIntentProof(
	t *testing.T, message string, out *wire.TxOut, notes int,
) *intent.Proof {
	t.Helper()

	inputs := make([]intent.Input, 0, notes)
	leafScripts := make([][]*psbt.TaprootTapLeafScript, 0, notes)
	preimages := make([][]byte, 0, notes)
	for range notes {
		preimage := make([]byte, 32)
		_, err := rand.Read(preimage)
		require.NoError(t, err)

		noteClosure := &note.NoteClosure{PreimageHash: sha256.Sum256(preimage)}
		noteScript, err := noteClosure.Script()
		require.NoError(t, err)

		leaf := txscript.NewBaseTapLeaf(noteScript)
		tapTree := txscript.AssembleTaprootScriptTree(leaf)
		root := tapTree.RootNode.TapHash()

		unspendableKey := script.UnspendableKey()
		p2trScript, err := script.P2TRScript(
			txscript.ComputeTaprootOutputKey(unspendableKey, root[:]),
		)
		require.NoError(t, err)

		leafIndex := tapTree.LeafProofIndex[leaf.TapHash()]
		cb := tapTree.LeafMerkleProofs[leafIndex].ToControlBlock(unspendableKey)
		controlBlock, err := cb.ToBytes()
		require.NoError(t, err)

		var prevHash [32]byte
		_, err = rand.Read(prevHash[:])
		require.NoError(t, err)

		inputs = append(inputs, intent.Input{
			OutPoint:    &wire.OutPoint{Hash: prevHash, Index: 0},
			WitnessUtxo: &wire.TxOut{Value: out.Value, PkScript: p2trScript},
		})
		leafScripts = append(leafScripts, []*psbt.TaprootTapLeafScript{{
			ControlBlock: controlBlock,
			Script:       noteScript,
			LeafVersion:  txscript.BaseLeafVersion,
		}})
		preimages = append(preimages, preimage)
	}

	proof, err := intent.New(message, inputs, []*wire.TxOut{out})
	require.NoError(t, err)

	// index 0 is the toSpend input, the ownership inputs follow from index 1
	proof.Inputs[0].TaprootLeafScript = leafScripts[0]
	for i := range notes {
		proof.Inputs[i+1].TaprootLeafScript = leafScripts[i]
		require.NoError(t, txutils.SetArkPsbtField(
			&proof.Packet, i+1, txutils.ConditionWitnessField, wire.TxWitness{preimages[i]},
		))
	}

	return proof
}

// The stubs below embed the port interfaces so they satisfy them with nil
// method sets, overriding only the methods the tests actually call.

type testWallet struct {
	ports.WalletService
	feeRate uint64
	feeErr  error
}

func (w testWallet) FeeRate(context.Context) (uint64, error) {
	return w.feeRate, w.feeErr
}

type testLiveStore struct {
	ports.LiveStore
	intents     ports.IntentStore
	settings    ports.SettingsStore
	offchainTxs ports.OffChainTxStore
	treeSigning ports.TreeSigningSessionsStore
}

// CosignedUtxos serves an empty store: no utxo is reserved by a cosign request in flight.
func (s testLiveStore) CosignedUtxos() ports.CosignedUtxosStore {
	return newTestCosignedUtxosStore()
}

func (s testLiveStore) Intents() ports.IntentStore { return s.intents }

func (s testLiveStore) Settings() ports.SettingsStore { return s.settings }

func (s testLiveStore) OffchainTxs() ports.OffChainTxStore { return s.offchainTxs }

func (s testLiveStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return s.treeSigning
}

// testTreeSigningStore serves session as the signing session of any round and records the
// nonces and signatures added to it, or refuses them with err.
type testTreeSigningStore struct {
	ports.TreeSigningSessionsStore
	session *ports.MusigSigningSession
	err     error
	nonces  map[string]tree.TreeNonces
	sigs    map[string]tree.TreePartialSigs
}

func (s *testTreeSigningStore) Get(context.Context, string) (*ports.MusigSigningSession, error) {
	return s.session, nil
}

func (s *testTreeSigningStore) AddNonces(
	_ context.Context, _ string, pubkey string, nonces tree.TreeNonces,
) error {
	if s.err != nil {
		return s.err
	}
	s.nonces[pubkey] = nonces
	return nil
}

func (s *testTreeSigningStore) AddSignatures(
	_ context.Context, _ string, pubkey string, sigs tree.TreePartialSigs,
) error {
	if s.err != nil {
		return s.err
	}
	s.sigs[pubkey] = sigs
	return nil
}

// testTreeSigningFixture builds a real one-leaf vtxo tree cosigned by a client key and the
// operator key, so nonces and signatures can be produced and verified for real, and a service
// serving its signing session from a recording store.
type testTreeSigningFixture struct {
	svc         *service
	store       *testTreeSigningStore
	session     *ports.MusigSigningSession
	roundId     string
	cosigner    string // client cosigner, hex encoded compressed key
	operator    string
	signer      tree.SignerSession // client signer session
	opSigner    tree.SignerSession
	coordinator tree.CoordinatorSession
}

func newTestTreeSigningFixture(t *testing.T) *testTreeSigningFixture {
	t.Helper()

	clientPrvkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	operatorPrvkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cosigner := hex.EncodeToString(clientPrvkey.PubKey().SerializeCompressed())
	operator := hex.EncodeToString(operatorPrvkey.PubKey().SerializeCompressed())

	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	sweepScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{operatorPrvkey.PubKey()},
		},
		Locktime: expiry,
	}).Script()
	require.NoError(t, err)
	scriptRoot := txscript.NewBaseTapLeaf(sweepScript).TapHash()

	receiverScript, err := script.P2TRScript(testPubkey(t))
	require.NoError(t, err)
	leaves := []tree.Leaf{{
		Outputs: []tree.LeafOutput{{
			Amount: 1000, Script: hex.EncodeToString(receiverScript),
		}},
		CosignersPublicKeys: []string{cosigner, operator},
	}}
	_, batchOutAmount, err := tree.BuildBatchOutput(leaves, scriptRoot[:])
	require.NoError(t, err)

	var rootInput wire.OutPoint
	_, err = rand.Read(rootInput.Hash[:])
	require.NoError(t, err)
	vtxoTree, err := tree.BuildVtxoTree(&rootInput, leaves, scriptRoot[:], expiry)
	require.NoError(t, err)
	flatTree, err := vtxoTree.Serialize()
	require.NoError(t, err)

	coordinator, err := tree.NewTreeCoordinatorSession(scriptRoot[:], batchOutAmount, vtxoTree)
	require.NoError(t, err)
	signer := tree.NewTreeSignerSession(clientPrvkey)
	require.NoError(t, signer.Init(scriptRoot[:], batchOutAmount, vtxoTree))
	opSigner := tree.NewTreeSignerSession(operatorPrvkey)
	require.NoError(t, opSigner.Init(scriptRoot[:], batchOutAmount, vtxoTree))

	session := &ports.MusigSigningSession{
		NbCosigners: 2,
		Cosigners:   map[string]struct{}{cosigner: {}, operator: {}},
		Nonces:      make(map[string]tree.TreeNonces),
		Signatures:  make(map[string]tree.TreePartialSigs),
		SigningContext: ports.SigningContext{
			ScriptRoot:     scriptRoot[:],
			BatchOutAmount: batchOutAmount,
			VtxoTree:       flatTree,
		},
	}
	store := &testTreeSigningStore{
		session: session,
		nonces:  make(map[string]tree.TreeNonces),
		sigs:    make(map[string]tree.TreePartialSigs),
	}

	return &testTreeSigningFixture{
		svc:         &service{cache: testLiveStore{treeSigning: store}},
		store:       store,
		session:     session,
		roundId:     "round-id",
		cosigner:    cosigner,
		operator:    operator,
		signer:      signer,
		opSigner:    opSigner,
		coordinator: coordinator,
	}
}

// aggregateNonces runs the nonce round for both cosigners and records its outcome in the
// session the way the batch does, so partial signatures can then be produced and verified.
func (f *testTreeSigningFixture) aggregateNonces(t *testing.T) {
	t.Helper()

	signers := map[string]tree.SignerSession{f.cosigner: f.signer, f.operator: f.opSigner}
	for pubkey, signer := range signers {
		nonces, err := signer.GetNonces()
		require.NoError(t, err)
		buf, err := hex.DecodeString(pubkey)
		require.NoError(t, err)
		pk, err := btcec.ParsePubKey(buf)
		require.NoError(t, err)
		f.coordinator.AddNonce(pk, nonces)
		f.session.Nonces[pubkey] = nonces
	}

	aggregated, err := f.coordinator.AggregateNonces()
	require.NoError(t, err)
	f.session.SigningContext.AggregatedNonces = aggregated
	for _, signer := range signers {
		signer.SetAggregatedNonces(aggregated)
	}
}

// nonces returns fresh nonces of the client cosigner for the tree.
func (f *testTreeSigningFixture) nonces(t *testing.T) tree.TreeNonces {
	t.Helper()
	nonces, err := f.signer.GetNonces()
	require.NoError(t, err)
	return nonces
}

// sigs runs the nonce round and returns the partial signatures of the client cosigner.
func (f *testTreeSigningFixture) sigs(t *testing.T) tree.TreePartialSigs {
	t.Helper()
	f.aggregateNonces(t)
	sigs, err := f.signer.Sign()
	require.NoError(t, err)
	return sigs
}

type testSettingsStore struct {
	ports.SettingsStore
	settings *ports.Settings
}

func (s testSettingsStore) Get(context.Context) (*ports.Settings, error) {
	return s.settings, nil
}

type testOffchainTxStore struct {
	ports.OffChainTxStore
}

func (s testOffchainTxStore) Remove(context.Context, string) error { return nil }

func (s testOffchainTxStore) IncludesAny(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	return nil, nil
}

type testIntentStore struct {
	ports.IntentStore
	intents []ports.TimedIntent
	err     error
}

func (s testIntentStore) ViewAll(
	context.Context, []string,
) ([]ports.TimedIntent, error) {
	return s.intents, s.err
}

func (s testIntentStore) IncludesAny(
	context.Context, []domain.Outpoint,
) ([]domain.Outpoint, error) {
	return nil, nil
}

// testSweptBatchFixture describes what the round repo and the wallet return for
// the batch of testSweepableRound.
type testSweptBatchFixture struct {
	expiredErr  error
	spent       bool
	spentErr    error
	vtxoTreeErr error
	rootTx      string
	rootTxErr   error
	sweepErr    error
}

type testSweptBatch struct {
	svc      *service
	rounds   *mockedRoundRepo
	wallet   *mockedWallet
	round    domain.Round
	rootTxid string
}

func testSweptBatchService(t *testing.T, fixture testSweptBatchFixture) testSweptBatch {
	t.Helper()
	round, rootTxid := testSweepableRound(t)
	batchOutput := domain.Outpoint{Txid: round.CommitmentTxid, VOut: 0}

	rounds := &mockedRoundRepo{}
	if fixture.expiredErr != nil {
		rounds.On("GetExpiredButNotSweptRounds", mock.Anything).Return(nil, fixture.expiredErr)
	} else {
		rounds.On("GetExpiredButNotSweptRounds", mock.Anything).
			Return([]string{round.CommitmentTxid}, nil)
	}
	if fixture.vtxoTreeErr != nil {
		rounds.On("GetRoundVtxoTree", mock.Anything, round.CommitmentTxid).
			Return(nil, fixture.vtxoTreeErr)
	} else {
		rounds.On("GetRoundVtxoTree", mock.Anything, round.CommitmentTxid).
			Return(round.VtxoTree, nil)
	}
	rounds.On("SweepRounds", mock.Anything, mock.Anything).Return(fixture.sweepErr)
	rm := &mockedRepoManager{}
	rm.On("Rounds").Return(rounds)
	wallet := &mockedWallet{}
	wallet.On("GetOutpointStatus", mock.Anything, batchOutput).
		Return(fixture.spent, fixture.spentErr)
	wallet.On("GetTransaction", mock.Anything, rootTxid).
		Return(fixture.rootTx, fixture.rootTxErr)

	return testSweptBatch{
		svc:      &service{repoManager: rm, wallet: wallet},
		rounds:   rounds,
		wallet:   wallet,
		round:    round,
		rootTxid: rootTxid,
	}
}

// testSweepableRound returns a round whose vtxo tree is a single tx with a vtxo
// and an anchor output, and the txid of that tx.
func testSweepableRound(t *testing.T) (domain.Round, string) {
	t.Helper()
	ptx, err := psbt.New(
		[]*wire.OutPoint{{Index: 0}},
		[]*wire.TxOut{{Value: 1000, PkScript: testP2TRScript(t)}, txutils.AnchorOutput()},
		3, 0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	rootTx, err := ptx.B64Encode()
	require.NoError(t, err)
	rootTxid := ptx.UnsignedTx.TxID()

	return domain.Round{
		Id:             "round",
		CommitmentTxid: "commitment",
		VtxoTree:       tree.FlatTxTree{{Txid: rootTxid, Tx: rootTx}},
	}, rootTxid
}
