package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/domain/batchtrigger"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
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
}

func TestSubmitOffchainTx(t *testing.T) {
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
}

func (s testLiveStore) Intents() ports.IntentStore { return s.intents }

func (s testLiveStore) Settings() ports.SettingsStore { return s.settings }

func (s testLiveStore) OffchainTxs() ports.OffChainTxStore { return s.offchainTxs }

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
