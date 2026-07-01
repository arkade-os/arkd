package application

import (
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// makeP2TRLeafTx creates a valid base64-encoded PSBT with P2TR outputs
// for the given schnorr public keys and amounts.
func makeP2TRLeafTx(t *testing.T, outputs []struct {
	pubkey *btcec.PublicKey
	amount int64
}) string {
	t.Helper()
	hash, err := chainhash.NewHashFromStr(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	require.NoError(t, err)

	txOuts := make([]*wire.TxOut, 0, len(outputs))
	for _, out := range outputs {
		pkScript := make([]byte, 34)
		pkScript[0] = 0x51 // OP_1
		pkScript[1] = 0x20 // 32-byte push
		copy(pkScript[2:], schnorr.SerializePubKey(out.pubkey))

		txOuts = append(txOuts, &wire.TxOut{
			Value:    out.amount,
			PkScript: pkScript,
		})
	}

	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *hash, Index: 0}},
		txOuts,
		3,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

// TestGetNewVtxosFromRound_MarkerIDsAndDepth verifies that getNewVtxosFromRound
// correctly assigns Depth=0 and MarkerIDs=[outpoint.String()] to every leaf VTXO
// produced from a round's VTXO tree. Also checks that commitment references, amounts,
// pubkeys, and sequential VOut indices are set correctly for multi-output leaf transactions.
func TestGetNewVtxosFromRound_MarkerIDsAndDepth(t *testing.T) {
	// Generate two distinct keys for two outputs
	privKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pub1 := privKey1.PubKey()
	pub2 := privKey2.PubKey()

	leafTx := makeP2TRLeafTx(t, []struct {
		pubkey *btcec.PublicKey
		amount int64
	}{
		{pubkey: pub1, amount: 50000},
		{pubkey: pub2, amount: 30000},
	})

	round := &domain.Round{
		CommitmentTxid:     "test-commitment-txid",
		VtxoTreeExpiration: 3600,
		EndingTimestamp:    1700000000,
		Stage:              domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
		VtxoTree: tree.FlatTxTree{
			{
				Txid:     "leaf-tx-id",
				Tx:       leafTx,
				Children: nil, // leaf node
			},
		},
	}

	vtxos := getNewVtxosFromRound(*round)

	require.Len(t, vtxos, 2)

	for i, vtxo := range vtxos {
		// All batch VTXOs must have Depth = 0
		require.Equal(t, uint32(0), vtxo.Depth, "vtxo %d should have depth 0", i)

		// MarkerIDs must be exactly []string{outpoint.String()}
		expectedMarkerID := vtxo.Outpoint.String()
		require.Equal(t, []string{expectedMarkerID}, vtxo.MarkerIDs,
			"vtxo %d MarkerIDs should be [outpoint.String()]", i)

		// CommitmentTxids should reference the round's commitment
		require.Equal(t, []string{"test-commitment-txid"}, vtxo.CommitmentTxids)
		require.Equal(t, "test-commitment-txid", vtxo.RootCommitmentTxid)

		// Amount must match
		if i == 0 {
			require.Equal(t, uint64(50000), vtxo.Amount)
		} else {
			require.Equal(t, uint64(30000), vtxo.Amount)
		}

		// PubKey must be non-empty
		require.NotEmpty(t, vtxo.PubKey)
	}

	// VOut should be sequential (0, 1)
	require.Equal(t, uint32(0), vtxos[0].VOut)
	require.Equal(t, uint32(1), vtxos[1].VOut)

	// Both should have the same txid (from the same PSBT)
	require.Equal(t, vtxos[0].Txid, vtxos[1].Txid)
}

// TestGetNewVtxosFromRound_EmptyVtxoTree verifies that a round with a nil VTXO tree
// returns nil, handling the edge case where no leaf transactions exist.
func TestGetNewVtxosFromRound_EmptyVtxoTree(t *testing.T) {
	round := &domain.Round{
		CommitmentTxid: "empty-round",
		VtxoTree:       nil,
	}

	vtxos := getNewVtxosFromRound(*round)
	require.Nil(t, vtxos)
}

// TestGetNewVtxosFromRound_SingleOutput verifies that a leaf transaction with a single
// P2TR output produces exactly one VTXO with Depth=0, the correct self-referencing
// MarkerID, the expected amount, and VOut=0.
func TestGetNewVtxosFromRound_SingleOutput(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	leafTx := makeP2TRLeafTx(t, []struct {
		pubkey *btcec.PublicKey
		amount int64
	}{
		{pubkey: privKey.PubKey(), amount: 100000},
	})

	round := &domain.Round{
		CommitmentTxid:     "single-output-commitment",
		VtxoTreeExpiration: 7200,
		EndingTimestamp:    1700000000,
		Stage:              domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
		VtxoTree: tree.FlatTxTree{
			{
				Txid:     "single-leaf",
				Tx:       leafTx,
				Children: nil,
			},
		},
	}

	vtxos := getNewVtxosFromRound(*round)
	require.Len(t, vtxos, 1)

	vtxo := vtxos[0]
	require.Equal(t, uint32(0), vtxo.Depth)
	require.Equal(t, []string{vtxo.Outpoint.String()}, vtxo.MarkerIDs)
	require.Equal(t, uint64(100000), vtxo.Amount)
	require.Equal(t, uint32(0), vtxo.VOut)
}

const bitcoinBlockWeight = 4_000_000

func TestMaxAssetsPerVtxo(t *testing.T) {
	tests := []struct {
		maxTxWeight uint64
		threshold   float32
		expected    int
	}{
		{maxTxWeight: 0.01 * bitcoinBlockWeight, threshold: 0.5, expected: 110},
		{maxTxWeight: 0.1 * bitcoinBlockWeight, threshold: 0.5, expected: 1110},
		{maxTxWeight: 0.5 * bitcoinBlockWeight, threshold: 0.5, expected: 5555},
		{maxTxWeight: bitcoinBlockWeight, threshold: 0.5, expected: 11110},
		{maxTxWeight: 0.01 * bitcoinBlockWeight, threshold: 0.25, expected: 55},
		{maxTxWeight: 0, threshold: 0.5, expected: 0},
	}

	for _, test := range tests {
		t.Run(
			fmt.Sprintf("maxTxWeight_%d_threshold_%.2f", test.maxTxWeight, test.threshold),
			func(t *testing.T) {
				s := domain.Settings{
					MaxTxWeight:           test.maxTxWeight,
					AssetTxMaxWeightRatio: test.threshold,
				}
				require.Equal(t, test.expected, s.MaxAssetsPerVtxo())
			},
		)
	}
}

func TestDecodeTx(t *testing.T) {
	zeroHash := chainhash.Hash{}

	validArkTx := mustEncodePSBTB64(t, newTestTx(
		[]wire.OutPoint{{Hash: zeroHash, Index: 0}},
		[][]byte{{0x51, 0x20, 0x01, 0x02}},
	))
	validCheckpointTx := mustEncodePSBTB64(t, newTestTx(
		[]wire.OutPoint{{Hash: zeroHash, Index: 1}},
		[][]byte{{0x51}},
	))

	t.Run("invalid", func(t *testing.T) {
		invalidFixtures := []struct {
			name        string
			offchainTx  domain.OffchainTx
			errorSubstr string
		}{
			{
				name: "rejects checkpoint with no inputs",
				offchainTx: domain.OffchainTx{
					ArkTx: validArkTx,
					CheckpointTxs: map[string]string{
						"cp0": mustEncodePSBTB64(t, newTestTx(nil, [][]byte{{0x51}})),
					},
				},
				errorSubstr: "missing inputs",
			},
			{
				name: "rejects short output script",
				offchainTx: domain.OffchainTx{
					ArkTx: mustEncodePSBTB64(t, newTestTx(
						[]wire.OutPoint{{Hash: zeroHash, Index: 0}},
						[][]byte{{0x6a}},
					)),
					CheckpointTxs: map[string]string{
						"cp0": validCheckpointTx,
					},
				},
				errorSubstr: "script too short",
			},
		}

		for _, fixture := range invalidFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				_, _, _, err := decodeTx(fixture.offchainTx)
				require.Error(t, err)
				require.Contains(t, err.Error(), fixture.errorSubstr)
			})
		}
	})

	t.Run("valid", func(t *testing.T) {
		validFixtures := []struct {
			name              string
			offchainTx        domain.OffchainTx
			expectedInsLen    int
			expectedInsVOut   uint32
			expectedOutsLen   int
			expectedOutsVOut  uint32
			expectedOutPubKey string
			expectedCreatedAt int64
			expectedExpiresAt int64
		}{
			{
				name: "decodes valid transaction",
				offchainTx: domain.OffchainTx{
					ArkTx: validArkTx,
					CheckpointTxs: map[string]string{
						"cp0": validCheckpointTx,
					},
					StartingTimestamp: 123,
					ExpiryTimestamp:   456,
				},
				expectedInsLen:    1,
				expectedInsVOut:   1,
				expectedOutsLen:   1,
				expectedOutsVOut:  0,
				expectedOutPubKey: "0102",
				expectedCreatedAt: 123,
				expectedExpiresAt: 456,
			},
		}

		for _, fixture := range validFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				txid, ins, outs, err := decodeTx(fixture.offchainTx)
				require.NoError(t, err)
				require.NotEmpty(t, txid)
				require.Len(t, ins, fixture.expectedInsLen)
				require.Equal(t, fixture.expectedInsVOut, ins[0].VOut)
				require.Len(t, outs, fixture.expectedOutsLen)
				require.Equal(t, txid, outs[0].Txid)
				require.Equal(t, fixture.expectedOutsVOut, outs[0].VOut)
				require.Equal(t, fixture.expectedOutPubKey, outs[0].PubKey)
				require.EqualValues(t, fixture.expectedCreatedAt, outs[0].CreatedAt)
				require.EqualValues(t, fixture.expectedExpiresAt, outs[0].ExpiresAt)
			})
		}
	})
}

func TestIsBoardingWitness(t *testing.T) {
	pubkey := append([]byte{0x02}, make([]byte, 32)...) // 33 bytes, not a control block
	controlBlock := append([]byte{0xc0}, make([]byte, 32)...)
	controlBlockParity := append([]byte{0xc1}, make([]byte, 32)...)
	controlBlockLong := append([]byte{0xc0}, make([]byte, 64)...) // 33 + 32

	tests := []struct {
		name    string
		witness wire.TxWitness
		want    bool
	}{
		{"script-path with sig", wire.TxWitness{[]byte("sig"), []byte("script"), controlBlock}, true},
		{"script-path minimal", wire.TxWitness{[]byte("script"), controlBlock}, true},
		{"script-path parity bit", wire.TxWitness{[]byte("script"), controlBlockParity}, true},
		{"script-path long control block", wire.TxWitness{[]byte("script"), controlBlockLong}, true},
		{"key-path single element", wire.TxWitness{make([]byte, 64)}, false},
		{"p2wpkh", wire.TxWitness{make([]byte, 72), pubkey}, false},
		{"empty witness", wire.TxWitness{}, false},
		{"bad control block length", wire.TxWitness{[]byte("script"), make([]byte, 34)}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isBoardingWitness(tc.witness))
		})
	}
}

func TestAcceptedSignerPubkeys(t *testing.T) {
	currentKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	current := currentKey.PubKey()

	deprecatedKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	deprecated := deprecatedKey.PubKey()

	otherKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	other := otherKey.PubKey()

	now := time.Now()

	t.Run("valid", func(t *testing.T) {
		validFixtures := []struct {
			name           string
			deprecatedKeys []ports.DeprecatedSignerPubkey
			expected       []*btcec.PublicKey
		}{
			{
				name:           "no deprecated keys",
				deprecatedKeys: nil,
				expected:       []*btcec.PublicKey{current},
			},
			{
				name: "no cutoff date",
				deprecatedKeys: []ports.DeprecatedSignerPubkey{
					{PubKey: deprecated},
				},
				expected: []*btcec.PublicKey{current, deprecated},
			},
			{
				name: "cutoff date in the future",
				deprecatedKeys: []ports.DeprecatedSignerPubkey{
					{PubKey: deprecated, CutoffDate: now.Add(time.Hour)},
				},
				expected: []*btcec.PublicKey{current, deprecated},
			},
		}

		for _, fixture := range validFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				pubkeys := acceptedSignerPubkeys(current, fixture.deprecatedKeys, now)
				require.Equal(t, fixture.expected, pubkeys)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		invalidFixtures := []struct {
			name           string
			deprecatedKeys []ports.DeprecatedSignerPubkey
			expected       []*btcec.PublicKey
		}{
			{
				name: "cutoff date in the past",
				deprecatedKeys: []ports.DeprecatedSignerPubkey{
					{PubKey: deprecated, CutoffDate: now.Add(-time.Hour)},
				},
				expected: []*btcec.PublicKey{current},
			},
			{
				name: "mixed cutoff dates",
				deprecatedKeys: []ports.DeprecatedSignerPubkey{
					{PubKey: deprecated, CutoffDate: now.Add(-time.Hour)},
					{PubKey: other, CutoffDate: now.Add(time.Hour)},
				},
				expected: []*btcec.PublicKey{current, other},
			},
		}

		for _, fixture := range invalidFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				pubkeys := acceptedSignerPubkeys(current, fixture.deprecatedKeys, now)
				require.Equal(t, fixture.expected, pubkeys)
			})
		}
	})
}

func TestValidateVtxoScriptForSigners(t *testing.T) {
	currentKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	current := currentKey.PubKey()

	deprecatedKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	deprecated := deprecatedKey.PubKey()

	ownerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	owner := ownerKey.PubKey()

	now := time.Now()
	exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}
	currentKeyScript := script.NewDefaultVtxoScript(owner, current, exitDelay)
	deprecatedKeyScript := script.NewDefaultVtxoScript(owner, deprecated, exitDelay)

	t.Run("valid", func(t *testing.T) {
		validFixtures := []struct {
			name           string
			vtxoScript     *script.TapscriptsVtxoScript
			deprecatedKeys []ports.DeprecatedSignerPubkey
		}{
			{
				name:       "current key",
				vtxoScript: currentKeyScript,
			},
			{
				name:       "deprecated key within cutoff",
				vtxoScript: deprecatedKeyScript,
				deprecatedKeys: []ports.DeprecatedSignerPubkey{
					{PubKey: deprecated, CutoffDate: now.Add(time.Hour)},
				},
			},
		}

		for _, fixture := range validFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				err := validateVtxoScriptForSigners(
					fixture.vtxoScript, current, fixture.deprecatedKeys, now, exitDelay, false,
				)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		pastCutoff := now.Add(-time.Hour)
		invalidFixtures := []struct {
			name           string
			deprecatedKeys []ports.DeprecatedSignerPubkey
			errorSubstr    string
		}{
			{
				name: "deprecated key past cutoff",
				deprecatedKeys: []ports.DeprecatedSignerPubkey{
					{PubKey: deprecated, CutoffDate: pastCutoff},
				},
				errorSubstr: fmt.Sprintf(
					"%x is a deprecated key since %s",
					deprecated.SerializeCompressed(), pastCutoff.Format(time.RFC3339),
				),
			},
			{
				name:           "unknown signer key",
				deprecatedKeys: nil,
				errorSubstr:    "signer pubkey not found",
			},
		}

		for _, fixture := range invalidFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				err := validateVtxoScriptForSigners(
					deprecatedKeyScript, current, fixture.deprecatedKeys, now, exitDelay, false,
				)
				require.Error(t, err)
				require.Contains(t, err.Error(), fixture.errorSubstr)
			})
		}
	})
}

func newTestTx(inputs []wire.OutPoint, scripts [][]byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	for _, in := range inputs {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: in,
			Sequence:         wire.MaxTxInSequenceNum,
		})
	}
	for _, script := range scripts {
		tx.AddTxOut(&wire.TxOut{
			Value:    1_000,
			PkScript: script,
		})
	}
	return tx
}

func mustEncodePSBTB64(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := p.B64Encode()
	require.NoError(t, err)
	return b64
}
