package txbuilder_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testingKey       = "020000000000000000000000000000000000000000000000000000000000000001"
	connectorAddress = "bc1py00yhcjpcj0k0sqra0etq0u3yy0purmspppsw0shyzyfe8c83tmq5h6kc2"
	forfeitPubkey    = "020000000000000000000000000000000000000000000000000000000000000002"
	changeAddress    = "bcrt1qhhq55mut9easvrncy4se8q6vg3crlug7yj4j56"

	// wallet mock behaviour: the change left by a selection, and the fee it estimates.
	// the change is above the dust limit so that the built tx always has a change output.
	selectionChange = 2000
	estimatedFee    = 100
)

var (
	wallet *mockedWallet
	pubkey *btcec.PublicKey

	vtxoTreeExpiry = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1209344}
)

func TestMain(m *testing.M) {
	wallet = &mockedWallet{}
	wallet.On("EstimateFees", mock.Anything, mock.Anything).
		Return(uint64(100), nil)
	wallet.On("SelectUtxos", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(randomInput, uint64(1000), nil)
	wallet.On("DeriveAddresses", mock.Anything, mock.Anything).
		Return([]string{changeAddress}, nil)
	wallet.On("DeriveConnectorAddress", mock.Anything).
		Return(connectorAddress, nil)
	wallet.On("GetDustAmount", mock.Anything).
		Return(uint64(1000), nil)
	wallet.On("GetForfeitPubkey", mock.Anything).
		Return(forfeitPubkey, nil)

	pubkeyBytes, _ := hex.DecodeString(testingKey)
	pubkey, _ = btcec.ParsePubKey(pubkeyBytes)

	os.Exit(m.Run())
}

func TestBuildCommitmentTx(t *testing.T) {
	fixtures, err := parseCommitmentTxFixtures()
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	if len(fixtures.Valid) > 0 {
		t.Run("valid", func(t *testing.T) {
			for _, f := range fixtures.Valid {
				cosignersPublicKeys := make([][]string, 0)

				for range f.Intents {
					randKey, err := btcec.NewPrivateKey()
					require.NoError(t, err)

					cosignersPublicKeys = append(cosignersPublicKeys, []string{
						hex.EncodeToString(randKey.PubKey().SerializeCompressed()),
					})
				}

				w, requested := newCoinSelectingWallet(selectionChange, estimatedFee)
				builder := txbuilder.NewTxBuilder(w, nil, arklib.Bitcoin)
				boardingInputs := newBoardingInputs(t, f.BoardingAmounts)

				commitmentTx, vtxoTree, connAddr, _, err := builder.BuildCommitmentTx(
					pubkey, f.Intents, boardingInputs, cosignersPublicKeys, vtxoTreeExpiry,
				)
				require.NoError(t, err)
				require.NotEmpty(t, commitmentTx)
				require.NotEmpty(t, vtxoTree)
				require.Equal(t, connectorAddress, connAddr)
				require.Len(t, vtxoTree.Leaves(), f.ExpectedNumOfLeaves)

				roundPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
				require.NoError(t, err)

				err = tree.ValidateVtxoTree(
					vtxoTree, roundPtx, pubkey, vtxoTreeExpiry,
				)
				require.NoError(t, err)

				w.AssertNumberOfCalls(t, "SelectUtxos", 1)
				require.Equal(t, f.ExpectedSelectionTarget, *requested)

				// whatever the target, inputs and outputs balance out to the fee: the
				// surplus of the boarding inputs is credited to the change, not lost.
				require.EqualValues(t, estimatedFee, txBalance(roundPtx))
			}
		})
	}

	if len(fixtures.Invalid) > 0 {
		t.Run("invalid", func(t *testing.T) {
			builder := txbuilder.NewTxBuilder(wallet, nil, arklib.Bitcoin)

			for _, f := range fixtures.Invalid {
				cosignersPublicKeys := make([][]string, 0)

				for range f.Intents {
					cosignersPublicKeys = append(cosignersPublicKeys, []string{
						hex.EncodeToString(pubkey.SerializeCompressed()),
					})
				}

				commitmentTx, vtxoTree, connAddr, _, err := builder.BuildCommitmentTx(
					pubkey, f.Intents, []ports.BoardingInput{}, cosignersPublicKeys,
					vtxoTreeExpiry,
				)
				require.EqualError(t, err, f.ExpectedErr)
				require.Empty(t, commitmentTx)
				require.Empty(t, connAddr)
				require.Empty(t, vtxoTree)
			}
		})
	}

	// the surplus is credited to the change before the dust check, so a surplus too small to
	// stand on its own still survives when the selection change carries it over the limit.
	// below the limit there is no output to hold it and it is paid to the miners instead.
	t.Run("surplus and dust limit", func(t *testing.T) {
		// the first fixture has no boarding input, its outputs are worth the target it pins
		f := fixtures.Valid[0]
		outputsAmount := f.ExpectedSelectionTarget

		tests := []struct {
			name            string
			surplus         uint64
			selectionChange uint64
			expectedOutputs int
			expectedChange  uint64
			expectedBalance uint64
		}{
			{
				name:            "surplus below dust carried over by the selection change",
				surplus:         500,
				selectionChange: 2000,
				expectedOutputs: 3,
				expectedChange:  2400,
				expectedBalance: estimatedFee,
			},
			{
				name:            "surplus and selection change below dust together",
				surplus:         500,
				selectionChange: 400,
				expectedOutputs: 2,
				expectedChange:  0,
				// 500 + 400, too small for an output so all of it goes to the miners
				expectedBalance: 900,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w, requested := newCoinSelectingWallet(tt.selectionChange, estimatedFee)
				builder := txbuilder.NewTxBuilder(w, nil, arklib.Bitcoin)
				boardingInputs := newBoardingInputs(t, []uint64{outputsAmount + tt.surplus})

				commitmentTx, _, _, _, err := builder.BuildCommitmentTx(
					pubkey, f.Intents, boardingInputs,
					newCosignerKeys(t, len(f.Intents)), vtxoTreeExpiry,
				)
				require.NoError(t, err)

				ptx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
				require.NoError(t, err)

				require.Zero(t, *requested)
				require.Len(t, ptx.UnsignedTx.TxOut, tt.expectedOutputs)
				if tt.expectedChange > 0 {
					lastOutput := ptx.UnsignedTx.TxOut[len(ptx.UnsignedTx.TxOut)-1]
					require.EqualValues(t, tt.expectedChange, lastOutput.Value)
				}
				require.EqualValues(t, tt.expectedBalance, txBalance(ptx))
			})
		}
	})
}

// TestBuildCommitmentTxUsesVtxoTreeExpiryArg pins that the vtxoTreeExpiry argument is what gets
// baked into the vtxo tree.
// ValidateVtxoTree derives the expected taproot output key from the expiry, so a tree built with
// one expiry fails validation against another; if BuildCommitmentTx ignored the argument this test
// would fail.
func TestBuildCommitmentTxUsesVtxoTreeExpiryArg(t *testing.T) {
	builder := txbuilder.NewTxBuilder(wallet, nil, arklib.Bitcoin)

	fixtures, err := parseCommitmentTxFixtures()
	require.NoError(t, err)
	require.NotEmpty(t, fixtures.Valid)

	// Pick a multi-leaf fixture: ValidateVtxoTree only checks the expiry-derived
	// taproot key on nodes that have children, so a single-leaf tree would not
	// exercise the expiry and the mismatch below would go undetected.
	best := 0
	for i, cand := range fixtures.Valid {
		if cand.ExpectedNumOfLeaves > fixtures.Valid[best].ExpectedNumOfLeaves {
			best = i
		}
	}
	f := fixtures.Valid[best]
	require.Greater(t, f.ExpectedNumOfLeaves, 1, "need a multi-leaf fixture to exercise the expiry")

	cosignersPublicKeys := make([][]string, 0, len(f.Intents))
	for range f.Intents {
		randKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		cosignersPublicKeys = append(cosignersPublicKeys, []string{
			hex.EncodeToString(randKey.PubKey().SerializeCompressed()),
		})
	}

	// Use an expiry distinct from the package default, so a regression that
	// reverted to a constructor-captured or hardcoded value would be caught.
	usedExpiry := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeSecond,
		Value: vtxoTreeExpiry.Value * 2,
	}
	require.NotEqual(t, vtxoTreeExpiry, usedExpiry)

	commitmentTx, vtxoTree, _, _, err := builder.BuildCommitmentTx(
		pubkey, f.Intents, []ports.BoardingInput{}, cosignersPublicKeys, usedExpiry,
	)
	require.NoError(t, err)

	roundPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	require.NoError(t, err)

	// The tree validates against the expiry it was built with, and not against
	// a different one, proving the argument determined the tree's timelock.
	require.NoError(t, tree.ValidateVtxoTree(vtxoTree, roundPtx, pubkey, usedExpiry))
	require.Error(t, tree.ValidateVtxoTree(vtxoTree, roundPtx, pubkey, vtxoTreeExpiry))
}

func TestVerifyVtxoTapscriptSigs(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	builder := txbuilder.NewTxBuilder(
		wallet, &staticSigner{pubkey: signerKey.PubKey()}, arklib.Bitcoin,
	)

	preimage := bytes.Repeat([]byte{0xAB}, 32)
	conditionCSVSetup, preimageWitness := newConditionCSVVtxoSetup(t, signerKey, preimage)

	t.Run("valid", func(t *testing.T) {
		t.Run("condition csv multisig accepted when condition is met", func(t *testing.T) {
			packet := buildTx(t, conditionCSVSetup, nil)
			require.NoError(t, txutils.SetArkPsbtField(
				packet, 0, txutils.ConditionWitnessField, preimageWitness,
			))

			sig := makeVtxoSig(t, conditionCSVSetup.closureKey, packet, conditionCSVSetup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			ok, ptx, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), false)
			require.NoError(t, err)
			require.True(t, ok)
			require.NotNil(t, ptx)
		})

		t.Run("input without taproot leaf script is skipped", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			tx := buildTx(t, setup, nil)
			tx.Inputs[0].TaprootLeafScript = nil

			ok, ptx, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, tx), false)
			require.NoError(t, err)
			require.True(t, ok)
			require.NotNil(t, ptx)
		})

		t.Run("signed input accepted with mustIncludeSignerSig=false", func(t *testing.T) {
			// 2-of-2 closure (closureKey + signerKey): signer is pre-marked, only closureKey needs to sign.
			setup := newTwoKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			ok, ptx, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), false)
			require.NoError(t, err)
			require.True(t, ok)
			require.NotNil(t, ptx)
		})

		t.Run("all keys signed accepted with mustIncludeSignerSig=true", func(t *testing.T) {
			// 2-of-2 closure: both keys must sign when signer is not pre-marked.
			setup := newTwoKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig1 := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			sig2 := makeVtxoSig(t, setup.signerKey, packet, setup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig1, sig2}

			ok, ptx, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), true)
			require.NoError(t, err)
			require.True(t, ok)
			require.NotNil(t, ptx)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("wrong parity bit in control block", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			corrupted := make([]byte, len(setup.cbBytes))
			copy(corrupted, setup.cbBytes)
			corrupted[0] ^= 0x01

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, buildTx(t, setup, corrupted)), false)
			require.Error(t, err)
		})

		t.Run("wrong x-coordinate from tampered merkle path", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			fakeNode := make([]byte, 32)
			_, err := rand.Read(fakeNode)
			require.NoError(t, err)

			corrupted := append(append([]byte{}, setup.cbBytes...), fakeNode...)
			_, _, err = builder.VerifyVtxoTapscriptSigs(encodeTx(t, buildTx(t, setup, corrupted)), false)
			require.Error(t, err)
		})

		t.Run("invalid signature", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			sig.Signature[0] ^= 0xff
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), false)
			require.Error(t, err)
		})

		t.Run("stripped leaf script when mustIncludeSignerSig=true", func(t *testing.T) {
			// Dropping the leaf script used to skip the input, so an unsigned
			// psbt passed as fully signed and left arkd unable to punish.
			setup := newSingleKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)
			packet.Inputs[0].TaprootLeafScript = nil

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), true)
			require.Error(t, err)
		})

		t.Run("condition csv multisig with unmet condition", func(t *testing.T) {
			packet := buildTx(t, conditionCSVSetup, nil)
			require.NoError(t, txutils.SetArkPsbtField(
				packet, 0, txutils.ConditionWitnessField,
				wire.TxWitness{bytes.Repeat([]byte{0xCD}, 32)}, // wrong preimage
			))

			sig := makeVtxoSig(t, conditionCSVSetup.closureKey, packet, conditionCSVSetup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), false)
			require.Error(t, err)
		})

		t.Run("condition csv multisig with met condition but no signature", func(t *testing.T) {
			// A met condition must not stand in for a signature: this closure
			// used to match no case in the verifier's type switch, so no required
			// keys were collected and the input passed with zero signatures
			// checked - the same bypass as a stripped leaf script, reached
			// through a leaf script that is present.
			packet := buildTx(t, conditionCSVSetup, nil)
			require.NoError(t, txutils.SetArkPsbtField(
				packet, 0, txutils.ConditionWitnessField, preimageWitness,
			))

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), true)
			require.Error(t, err)
		})

		t.Run("missing signer signature when mustIncludeSignerSig=true", func(t *testing.T) {
			// 2-of-2 closure: signer is not pre-marked and doesn't sign → error.
			setup := newTwoKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), true)
			require.Error(t, err)
		})
	})
}

type commitmentTxFixtures struct {
	Valid []struct {
		Intents                 []domain.Intent
		BoardingAmounts         []uint64
		ExpectedSelectionTarget uint64
		ExpectedNumOfLeaves     int
	}
	Invalid []struct {
		Intents     []domain.Intent
		ExpectedErr string
	}
}

func parseCommitmentTxFixtures() (*commitmentTxFixtures, error) {
	file, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		return nil, err
	}
	var v struct {
		BuildCommitmentTx commitmentTxFixtures `json:"buildCommitmentTx"`
	}
	if err := json.Unmarshal(file, &v); err != nil {
		return nil, err
	}

	return &v.BuildCommitmentTx, nil
}

// newCoinSelectingWallet returns a wallet mock whose SelectUtxos honours the wallet contract,
// ie. it returns a single utxo worth the requested amount plus change, together with the last
// amount it has been asked for.
func newCoinSelectingWallet(change, fees uint64) (*mockedWallet, *uint64) {
	requested := uint64(0)

	w := &mockedWallet{}
	w.On("GetDustAmount", mock.Anything).Return(uint64(1000), nil)
	w.On("EstimateFees", mock.Anything, mock.Anything).Return(fees, nil)
	w.On("DeriveAddresses", mock.Anything, mock.Anything).Return([]string{changeAddress}, nil)
	w.On("DeriveConnectorAddress", mock.Anything).Return(connectorAddress, nil)
	w.On("GetForfeitPubkey", mock.Anything).Return(forfeitPubkey, nil)
	w.On("SelectUtxos", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			requested = args.Get(2).(uint64)
		}).
		Return(func() []ports.TxInput {
			return []ports.TxInput{{
				Txid:   randomHex(32),
				Index:  0,
				Script: "a914ea9f486e82efb3dd83a69fd96e3f0113757da03c87",
				Value:  requested + change,
			}}
		}, change, nil)

	return w, &requested
}

// newCosignerKeys builds one random cosigner key per intent.
func newCosignerKeys(t *testing.T, numOfIntents int) [][]string {
	t.Helper()

	keys := make([][]string, 0, numOfIntents)
	for range numOfIntents {
		randKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		keys = append(keys, []string{
			hex.EncodeToString(randKey.PubKey().SerializeCompressed()),
		})
	}

	return keys
}

// newBoardingInputs builds boarding inputs of the given amounts, all locked by the same random key.
func newBoardingInputs(t *testing.T, amounts []uint64) []ports.BoardingInput {
	t.Helper()

	boardingKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	boardingScript, err := (&script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{boardingKey.PubKey()},
		Type:    script.MultisigTypeChecksig,
	}).Script()
	require.NoError(t, err)

	inputs := make([]ports.BoardingInput, 0, len(amounts))
	for _, amount := range amounts {
		inputs = append(inputs, ports.BoardingInput{
			Input: ports.Input{
				Outpoint:   domain.Outpoint{Txid: randomHex(32), VOut: 0},
				Tapscripts: []string{hex.EncodeToString(boardingScript)},
			},
			Amount: amount,
		})
	}

	return inputs
}

// txBalance returns the amount left to the miners, ie. inputs minus outputs.
func txBalance(ptx *psbt.Packet) int64 {
	balance := int64(0)
	for _, in := range ptx.Inputs {
		balance += in.WitnessUtxo.Value
	}
	for _, out := range ptx.UnsignedTx.TxOut {
		balance -= out.Value
	}
	return balance
}

func TestVerifyBoardingTapscriptSigsBindsToCommitmentTx(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	builder := txbuilder.NewTxBuilder(
		wallet, &staticSigner{pubkey: signerKey.PubKey()}, arklib.Bitcoin,
	)

	// a boarding input the operator and the user co-sign
	setup := newTwoKeyVtxoSetup(t, signerKey)
	commitment := buildTx(t, setup, nil)
	commitmentB64 := encodeTx(t, commitment)

	signWith := func(packet *psbt.Packet) string {
		t.Helper()
		sig := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
		packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
		return encodeTx(t, packet)
	}

	t.Run("signature over the operator's tx is accepted", func(t *testing.T) {
		honest := clonePacket(t, commitment)

		ins, err := builder.VerifyBoardingTapscriptSigs(signWith(honest), commitmentB64)
		require.NoError(t, err)
		require.Len(t, ins, 1)
	})

	t.Run("signature over a modified tx is refused", func(t *testing.T) {
		modified := clonePacket(t, commitment)
		modified.UnsignedTx.TxOut[0].Value--
		require.NotEqual(t, commitment.UnsignedTx.TxID(), modified.UnsignedTx.TxID())

		// the signature is cryptographically valid, just for the wrong transaction
		_, err := builder.VerifyBoardingTapscriptSigs(signWith(modified), commitmentB64)
		require.ErrorContains(t, err, "commitment tx mismatch")
	})

	t.Run("signature over a tx with an extra output is refused", func(t *testing.T) {
		modified := clonePacket(t, commitment)
		modified.UnsignedTx.AddTxOut(wire.NewTxOut(500, setup.p2trScript))
		modified.Outputs = append(modified.Outputs, psbt.POutput{})

		_, err := builder.VerifyBoardingTapscriptSigs(signWith(modified), commitmentB64)
		require.ErrorContains(t, err, "commitment tx mismatch")
	})
}

// clonePacket deep copies a psbt through its serialization.
func clonePacket(t *testing.T, p *psbt.Packet) *psbt.Packet {
	t.Helper()
	clone, err := psbt.NewFromRawBytes(strings.NewReader(encodeTx(t, p)), true)
	require.NoError(t, err)
	return clone
}
