package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"sync"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A boarding-only intent has no virtual inputs, so a proof over its boarding
// outpoint has to be matched against BoardingInputs or the intent can never be
// deleted. These tests drive DeleteIntentsByProof against an in-test intent
// queue, with the proof inputs resolved as boarding utxos (no vtxo found, tx
// read from the wallet) or as vtxos (found in the repo).
func TestDeleteIntentsByProof(t *testing.T) {
	message := intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete},
	}
	encodedMessage, err := message.Encode()
	require.NoError(t, err)

	out := &wire.TxOut{Value: int64(testDust) * 2, PkScript: make([]byte, 34)}

	t.Run("valid", func(t *testing.T) {
		t.Run("intent with only boarding inputs", func(t *testing.T) {
			ctx := t.Context()
			proof := testNoteIntentProof(t, encodedMessage, out)
			boarding := proofBoardingInputs(t, proof)

			f := newDeleteIntentFixture(t, proof, nil)
			require.NoError(t, f.intents.Push(
				ctx, domain.Intent{Id: "boarding-only"}, boarding, nil,
			))

			require.Nil(t, f.svc.DeleteIntentsByProof(ctx, *proof, message))

			remaining, err := f.intents.ViewAll(ctx, nil)
			require.NoError(t, err)
			require.Empty(t, remaining)
			require.Equal(t, [][]string{{"boarding-only"}}, f.intents.deleted)
		})

		t.Run("intent with boarding inputs and other intents in the queue", func(t *testing.T) {
			ctx := t.Context()
			proof := testNoteIntentProof(t, encodedMessage, out)
			boarding := proofBoardingInputs(t, proof)

			f := newDeleteIntentFixture(t, proof, nil)
			require.NoError(t, f.intents.Push(ctx, domain.Intent{Id: "matched"}, boarding, nil))
			require.NoError(t, f.intents.Push(
				ctx, domain.Intent{Id: "sibling"},
				[]ports.BoardingInput{randomBoardingInput(t)}, nil,
			))

			require.Nil(t, f.svc.DeleteIntentsByProof(ctx, *proof, message))

			remaining, err := f.intents.ViewAll(ctx, nil)
			require.NoError(t, err)
			require.Len(t, remaining, 1)
			require.Equal(t, "sibling", remaining[0].Id)
			require.Equal(t, [][]string{{"matched"}}, f.intents.deleted)
		})

		t.Run("intent with mixed inputs and proof covers both", func(t *testing.T) {
			ctx := t.Context()
			// input 1 is resolved as a vtxo, input 2 as a boarding utxo
			proof := testNotesIntentProof(t, encodedMessage, out, 2)
			vtxo := proofVtxo(t, proof, 1)
			boarding := proofBoardingInputs(t, proof)[1:]

			f := newDeleteIntentFixture(t, proof, []domain.Vtxo{vtxo})
			require.NoError(t, f.intents.Push(
				ctx, domain.Intent{Id: "mixed", Inputs: []domain.Vtxo{vtxo}}, boarding, nil,
			))

			require.Nil(t, f.svc.DeleteIntentsByProof(ctx, *proof, message))

			remaining, err := f.intents.ViewAll(ctx, nil)
			require.NoError(t, err)
			require.Empty(t, remaining)
			// matched by both its vtxo and its boarding input, but deleted once
			require.Equal(t, [][]string{{"mixed"}}, f.intents.deleted)
		})

		t.Run("intent with mixed inputs and proof covers the boarding only", func(t *testing.T) {
			ctx := t.Context()
			proof := testNoteIntentProof(t, encodedMessage, out)
			boarding := proofBoardingInputs(t, proof)
			vtxo := domain.Vtxo{
				Outpoint: randomBoardingInput(t).Outpoint, Amount: uint64(out.Value),
			}

			f := newDeleteIntentFixture(t, proof, nil)
			require.NoError(t, f.intents.Push(
				ctx, domain.Intent{Id: "mixed", Inputs: []domain.Vtxo{vtxo}}, boarding, nil,
			))

			require.Nil(t, f.svc.DeleteIntentsByProof(ctx, *proof, message))

			remaining, err := f.intents.ViewAll(ctx, nil)
			require.NoError(t, err)
			require.Empty(t, remaining)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("proof covers an outpoint not in the queue", func(t *testing.T) {
			ctx := t.Context()
			proof := testNoteIntentProof(t, encodedMessage, out)

			f := newDeleteIntentFixture(t, proof, nil)
			require.NoError(t, f.intents.Push(
				ctx, domain.Intent{Id: "other"},
				[]ports.BoardingInput{randomBoardingInput(t)}, nil,
			))

			appErr := f.svc.DeleteIntentsByProof(ctx, *proof, message)
			require.Error(t, appErr)
			require.Equal(t, errors.INVALID_INTENT_PROOF.Code, appErr.Code())
			require.ErrorContains(t, appErr, "no matching intents found for intent proof")

			remaining, err := f.intents.ViewAll(ctx, nil)
			require.NoError(t, err)
			require.Len(t, remaining, 1)
			require.Empty(t, f.intents.deleted)
		})

		t.Run("proof covers the same txid with a different vout", func(t *testing.T) {
			ctx := t.Context()
			proof := testNoteIntentProof(t, encodedMessage, out)
			boarding := proofBoardingInputs(t, proof)
			boarding[0].VOut++

			f := newDeleteIntentFixture(t, proof, nil)
			require.NoError(t, f.intents.Push(
				ctx, domain.Intent{Id: "other-vout"}, boarding, nil,
			))

			appErr := f.svc.DeleteIntentsByProof(ctx, *proof, message)
			require.Error(t, appErr)
			require.Equal(t, errors.INVALID_INTENT_PROOF.Code, appErr.Code())

			remaining, err := f.intents.ViewAll(ctx, nil)
			require.NoError(t, err)
			require.Len(t, remaining, 1)
			require.Empty(t, f.intents.deleted)
		})

		t.Run("proof signed with csv delayed leaf", func(t *testing.T) {
			ctx := t.Context()
			proof := signedCSVIntentProof(t, newCosignFixture(t), encodedMessage)

			f := newDeleteIntentFixture(t, proof, nil)
			require.NoError(t, f.intents.Push(
				ctx, domain.Intent{Id: "csv"}, proofBoardingInputs(t, proof), nil,
			))

			appErr := f.svc.DeleteIntentsByProof(ctx, *proof, message)
			require.Error(t, appErr)
			require.Equal(t, errors.INVALID_PSBT_INPUT.Code, appErr.Code())
			require.ErrorContains(t, appErr, "CSV")

			remaining, err := f.intents.ViewAll(ctx, nil)
			require.NoError(t, err)
			require.Len(t, remaining, 1)
			require.Empty(t, f.intents.deleted)
		})
	})
}

func TestCSVIntentAdmissionRejectsSelectedLeaf(t *testing.T) {
	f := newCosignFixture(t)
	registration := f.registration(t).message
	encoded, err := registration.Encode()
	require.NoError(t, err)
	proof := signedCSVIntentProof(t, f, encoded)

	_, appErr := f.svc.RegisterIntent(t.Context(), *proof, registration)
	require.Error(t, appErr)
	require.Equal(t, errors.INVALID_PSBT_INPUT.Code, appErr.Code())
	require.ErrorContains(t, appErr, "CSV")

	estimate := intent.EstimateIntentFeeMessage(registration)
	estimate.Type = intent.IntentMessageTypeEstimateFee
	encoded, err = estimate.Encode()
	require.NoError(t, err)
	proof = signedCSVIntentProof(t, f, encoded)

	_, appErr = f.svc.EstimateIntentFee(t.Context(), *proof, estimate)
	require.Error(t, appErr)
	require.Equal(t, errors.INVALID_PSBT_INPUT.Code, appErr.Code())
	require.ErrorContains(t, appErr, "CSV")
}

func signedCSVIntentProof(t *testing.T, f *cosignFixture, encodedMessage string) *intent.Proof {
	t.Helper()
	hash, err := chainhash.NewHashFromStr(f.utxo.Txid)
	require.NoError(t, err)
	sequence, err := arklib.BIP68Sequence(f.exitDelay)
	require.NoError(t, err)
	proof, err := intent.New(encodedMessage, []intent.Input{{
		OutPoint: &wire.OutPoint{Hash: *hash, Index: f.utxo.VOut}, Sequence: sequence,
		WitnessUtxo: &wire.TxOut{Value: int64(f.amount), PkScript: f.pkScript},
	}}, []*wire.TxOut{{Value: int64(f.amount), PkScript: testP2TRScript(t)}})
	require.NoError(t, err)
	for i, leaf := range []*psbt.TaprootTapLeafScript{f.forfeitLeaf, f.exitLeaf} {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{leaf}
		proof.Inputs[i].TaprootScriptSpendSig = f.ownerSigs(t, &proof.Packet, i, leaf)
	}
	return proof
}

type deleteIntentFixture struct {
	svc     *service
	intents *recordingIntentStore
}

// newDeleteIntentFixture wires a service whose repo resolves knownVtxos and
// nothing else, and whose wallet serves every proof input as the output 0 of
// its own boarding tx.
func newDeleteIntentFixture(
	t *testing.T, proof *intent.Proof, knownVtxos []domain.Vtxo,
) deleteIntentFixture {
	t.Helper()

	vtxos := &mockedVtxoRepo{}
	for _, vtxo := range knownVtxos {
		vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{vtxo.Outpoint}).
			Return([]domain.Vtxo{vtxo}, nil)
	}
	vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(nil, nil)
	repos := &mockedRepoManager{}
	repos.On("Vtxos").Return(vtxos)

	wallet := &mockedWallet{}
	for i, outpoint := range proof.GetOutpoints() {
		wallet.On("GetTransaction", mock.Anything, outpoint.Hash.String()).
			Return(boardingTxHex(t, proof.Inputs[i+1].WitnessUtxo), nil)
	}

	intents := &recordingIntentStore{}

	return deleteIntentFixture{
		svc: &service{
			repoManager:  repos,
			wallet:       wallet,
			offchainTxMu: &sync.Mutex{},
			cache: testLiveStore{
				intents:     intents,
				settings:    registerIntentTestSettings(t),
				offchainTxs: testOffchainTxStore{},
			},
		},
		intents: intents,
	}
}

// recordingIntentStore is an intent queue that keeps the id batches passed to
// Delete.
type recordingIntentStore struct {
	ports.IntentStore
	intents []ports.TimedIntent
	deleted [][]string
}

func (s *recordingIntentStore) Push(
	_ context.Context, intent domain.Intent, boardingInputs []ports.BoardingInput, _ []string,
) error {
	s.intents = append(s.intents, ports.TimedIntent{
		Intent: intent, BoardingInputs: boardingInputs,
	})
	return nil
}

func (s *recordingIntentStore) ViewAll(context.Context, []string) ([]ports.TimedIntent, error) {
	return slices.Clone(s.intents), nil
}

func (s *recordingIntentStore) Delete(_ context.Context, ids []string) error {
	s.deleted = append(s.deleted, ids)
	s.intents = slices.DeleteFunc(s.intents, func(intent ports.TimedIntent) bool {
		return slices.Contains(ids, intent.Id)
	})
	return nil
}

// proofBoardingInputs returns the proof's ownership outpoints as boarding inputs.
func proofBoardingInputs(t *testing.T, proof *intent.Proof) []ports.BoardingInput {
	t.Helper()

	outpoints := proof.GetOutpoints()
	inputs := make([]ports.BoardingInput, 0, len(outpoints))
	for i, outpoint := range outpoints {
		inputs = append(inputs, ports.BoardingInput{
			Input: ports.Input{Outpoint: domain.Outpoint{
				Txid: outpoint.Hash.String(), VOut: outpoint.Index,
			}},
			Amount: uint64(proof.Inputs[i+1].WitnessUtxo.Value),
		})
	}
	return inputs
}

// proofVtxo returns the vtxo the ownership input at psbt index i would spend:
// same outpoint and amount, pubkey read off the taproot output script.
func proofVtxo(t *testing.T, proof *intent.Proof, i int) domain.Vtxo {
	t.Helper()

	outpoint := proof.UnsignedTx.TxIn[i].PreviousOutPoint
	witnessUtxo := proof.Inputs[i].WitnessUtxo
	return domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: outpoint.Hash.String(), VOut: outpoint.Index},
		Amount:   uint64(witnessUtxo.Value),
		PubKey:   hex.EncodeToString(witnessUtxo.PkScript[2:]),
	}
}

func randomBoardingInput(t *testing.T) ports.BoardingInput {
	t.Helper()

	var txid [32]byte
	_, err := rand.Read(txid[:])
	require.NoError(t, err)
	return ports.BoardingInput{
		Input: ports.Input{Outpoint: domain.Outpoint{
			Txid: hex.EncodeToString(txid[:]), VOut: 0,
		}},
		Amount: testDust,
	}
}

// boardingTxHex serializes a tx whose output 0 is out, as the wallet would
// return the boarding tx funding a proof input.
func boardingTxHex(t *testing.T, out *wire.TxOut) string {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(out)

	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}
