package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// mockVtxoRepo implements GetVtxos for intent proof validation.
type mockVtxoRepo struct {
	domain.VtxoRepository
	vtxos map[string]domain.Vtxo // "txid:vout" -> Vtxo
}

func (m *mockVtxoRepo) GetVtxos(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	result := make([]domain.Vtxo, 0)
	for _, op := range outpoints {
		key := op.String()
		if vtxo, ok := m.vtxos[key]; ok {
			result = append(result, vtxo)
		}
	}
	return result, nil
}

type mockRepoManagerWithVtxos struct {
	mockRepoManager
	vtxos *mockVtxoRepo
}

func (m *mockRepoManagerWithVtxos) Vtxos() domain.VtxoRepository { return m.vtxos }

// mockWallet returns "not found" for all tx lookups.
type mockWallet struct {
	ports.WalletService
}

func (m *mockWallet) GetTransaction(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("tx not found")
}

// buildTestIntent creates a minimal valid intent PSBT for testing.
// The PSBT structure: input[0] = toSpend (dummy), input[1] = vtxo being proved.
func buildTestIntent(
	t *testing.T, vtxoTxid string, vtxoVout uint32, pkScript []byte, amount int64,
) Intent {
	t.Helper()

	vtxoHash, err := chainhash.NewHashFromStr(vtxoTxid)
	require.NoError(t, err)

	// Build a minimal 2-input PSBT: input 0 is the "toSpend" dummy, input 1 is the vtxo
	unsignedTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0}},
			{PreviousOutPoint: wire.OutPoint{Hash: *vtxoHash, Index: vtxoVout}},
		},
		TxOut: []*wire.TxOut{
			{Value: amount, PkScript: pkScript},
		},
	}

	ptx, err := psbt.New(
		[]*wire.OutPoint{
			{Hash: chainhash.Hash{0x01}, Index: 0},
			{Hash: *vtxoHash, Index: vtxoVout},
		},
		unsignedTx.TxOut,
		unsignedTx.Version,
		unsignedTx.LockTime,
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	// Add required fields on input 1 (the vtxo input)
	dummyScript := []byte{txscript.OP_TRUE}

	// Build a valid control block: leaf_version|parity (1 byte) + internal key (32 bytes)
	dummyInternalKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	controlBlock := make([]byte, 33)
	controlBlock[0] = byte(txscript.BaseLeafVersion) // 0xc0
	copy(controlBlock[1:], schnorr.SerializePubKey(dummyInternalKey.PubKey()))

	ptx.Inputs[1].WitnessUtxo = &wire.TxOut{
		Value:    amount,
		PkScript: pkScript,
	}
	ptx.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlock,
			Script:       dummyScript,
			LeafVersion:  txscript.BaseLeafVersion,
		},
	}

	b64, err := ptx.B64Encode()
	require.NoError(t, err)

	return Intent{
		Proof:   b64,
		Message: "test-message",
	}
}

// vtxoKey formats an outpoint as "txid:vout" matching domain.Outpoint.String().
func vtxoKey(txid string, vout uint32) string {
	return domain.Outpoint{Txid: txid, VOut: vout}.String()
}

func newTestIndexerWithVtxos(
	t *testing.T, privkey *btcec.PrivateKey, exposure string,
	vtxos map[string]domain.Vtxo, rounds map[string]string,
) *indexerService {
	t.Helper()
	return &indexerService{
		repoManager: &mockRepoManagerWithVtxos{
			mockRepoManager: mockRepoManager{
				rounds: &mockRoundRepo{txs: rounds},
			},
			vtxos: &mockVtxoRepo{vtxos: vtxos},
		},
		wallet:       &mockWallet{},
		privkey:      privkey,
		authPubkey:   schnorr.SerializePubKey(privkey.PubKey()),
		txExposure:   exposure,
		authTokenTTL: defaultAuthTokenTTL,
	}
}

var (
	testVtxoTxid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testVtxoVout = uint32(0)
)

func TestGetVirtualTxs_IntentPrivateExposure(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	vtxoPubkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := arkscript.P2TRScript(vtxoPubkey.PubKey())
	require.NoError(t, err)

	vtxoAmount := int64(21000)

	vtxos := map[string]domain.Vtxo{
		vtxoKey(testVtxoTxid, testVtxoVout): {
			Outpoint: domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
			Amount:   uint64(vtxoAmount),
			PubKey:   hex.EncodeToString(schnorr.SerializePubKey(vtxoPubkey.PubKey())),
			RootCommitmentTxid: testTxids[0],
		},
	}

	rounds := map[string]string{
		testTxids[0]: "fakeTxData",
	}

	validIntent := buildTestIntent(t, testVtxoTxid, testVtxoVout, pkScript, vtxoAmount)

	t.Run("valid intent succeeds", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, rounds)
		// Request the vtxo's own txid which is in its chain
		_, err := indexer.GetVirtualTxs(
			context.Background(), "", validIntent, []string{testVtxoTxid}, nil,
		)
		// validateTxidsAgainstChain will fail because buildVtxoChain needs
		// a full tree, but the intent validation itself succeeds.
		// The error should be about the chain, not about auth.
		require.Error(t, err)
		require.NotContains(t, err.Error(), "auth token or intent is required")
		require.NotContains(t, err.Error(), "invalid auth token or intent")
	})

	t.Run("invalid intent proof rejected", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, rounds)
		badIntent := Intent{Proof: "notavalidpsbt", Message: "test"}
		_, err := indexer.GetVirtualTxs(
			context.Background(), "", badIntent, testTxids, nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth token or intent")
	})

	t.Run("empty intent and empty token rejected", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, rounds)
		_, err := indexer.GetVirtualTxs(
			context.Background(), "", Intent{}, testTxids, nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "auth token or intent is required")
	})

	t.Run("bad token falls back to valid intent", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, rounds)
		// bad auth token + valid intent: should succeed via intent fallback
		_, err := indexer.GetVirtualTxs(
			context.Background(), "badtoken", validIntent, []string{testVtxoTxid}, nil,
		)
		// Should pass auth (resolved via intent) but may fail on chain validation
		require.Error(t, err)
		require.NotContains(t, err.Error(), "invalid auth token or intent")
	})

	t.Run("valid token takes priority over intent", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, rounds)
		// Create a valid auth token for a different outpoint
		token, err := indexer.createAuthToken(Outpoint{Txid: testTxids[0], VOut: 0})
		require.NoError(t, err)

		// valid token + valid intent: token wins, chain validation uses token's outpoint
		_, err = indexer.GetVirtualTxs(
			context.Background(), token, validIntent, testTxids, nil,
		)
		// Passes auth via token. Chain validation may fail but not an auth error.
		require.Error(t, err)
		require.NotContains(t, err.Error(), "invalid auth token or intent")
	})

	t.Run("both bad token and bad intent rejected", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, rounds)
		badIntent := Intent{Proof: "notavalidpsbt", Message: "test"}
		_, err := indexer.GetVirtualTxs(
			context.Background(), "badtoken", badIntent, testTxids, nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth token or intent")
	})
}

func TestGetVirtualTxs_IntentWithheldExposure(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	vtxoPubkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := arkscript.P2TRScript(vtxoPubkey.PubKey())
	require.NoError(t, err)

	vtxoAmount := int64(21000)

	vtxos := map[string]domain.Vtxo{
		vtxoKey(testVtxoTxid, testVtxoVout): {
			Outpoint: domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
			Amount:   uint64(vtxoAmount),
			PubKey:   hex.EncodeToString(schnorr.SerializePubKey(vtxoPubkey.PubKey())),
			RootCommitmentTxid: testTxids[0],
		},
	}

	validIntent := buildTestIntent(t, testVtxoTxid, testVtxoVout, pkScript, vtxoAmount)

	t.Run("invalid intent degrades gracefully", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "withheld", vtxos, map[string]string{})
		badIntent := Intent{Proof: "notavalidpsbt", Message: "test"}
		// withheld: bad intent should not error, just strip signatures
		resp, err := indexer.GetVirtualTxs(
			context.Background(), "", badIntent, nil, nil,
		)
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("bad token falls back to valid intent", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "withheld", vtxos, map[string]string{})
		// bad token + valid intent: should resolve via intent
		_, err := indexer.GetVirtualTxs(
			context.Background(), "badtoken", validIntent, []string{testVtxoTxid}, nil,
		)
		// Auth resolves via intent, then chain validation runs (may fail on tree)
		// but should NOT degrade to stripped signatures path
		require.Error(t, err)
		// Error is from chain validation, not from auth
		require.NotContains(t, err.Error(), "invalid auth token or intent")
	})

	t.Run("both empty degrades gracefully", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "withheld", vtxos, map[string]string{})
		resp, err := indexer.GetVirtualTxs(
			context.Background(), "", Intent{}, nil, nil,
		)
		require.NoError(t, err)
		require.NotNil(t, resp)
	})
}

func TestGetVirtualTxs_IntentPublicExposure(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	repo := &mockRepoManager{
		rounds: &mockRoundRepo{txs: map[string]string{
			testTxids[0]: "fakeTxData",
		}},
	}
	indexer := newTestIndexerWithExposure(privkey, "public", repo)

	t.Run("intent is ignored in public mode", func(t *testing.T) {
		badIntent := Intent{Proof: "notavalidpsbt", Message: "test"}
		resp, err := indexer.GetVirtualTxs(
			context.Background(), "", badIntent, testTxids, nil,
		)
		require.NoError(t, err)
		require.Len(t, resp.Txs, 1)
	})
}

func TestGetVirtualTxs_IntentAmountMismatch(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	vtxoPubkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := arkscript.P2TRScript(vtxoPubkey.PubKey())
	require.NoError(t, err)

	vtxos := map[string]domain.Vtxo{
		vtxoKey(testVtxoTxid, testVtxoVout): {
			Outpoint: domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
			Amount:   21000,
			PubKey:   hex.EncodeToString(schnorr.SerializePubKey(vtxoPubkey.PubKey())),
		},
	}

	t.Run("private: wrong amount in intent rejected", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, map[string]string{})
		// Intent claims 99999 but vtxo has 21000
		wrongAmountIntent := buildTestIntent(t, testVtxoTxid, testVtxoVout, pkScript, 99999)
		_, err := indexer.GetVirtualTxs(
			context.Background(), "", wrongAmountIntent, testTxids, nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth token or intent")
	})
}

func TestGetVirtualTxs_IntentPkScriptMismatch(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	vtxoPubkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	differentPubkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wrongPkScript, err := arkscript.P2TRScript(differentPubkey.PubKey())
	require.NoError(t, err)

	vtxos := map[string]domain.Vtxo{
		vtxoKey(testVtxoTxid, testVtxoVout): {
			Outpoint: domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
			Amount:   21000,
			PubKey:   hex.EncodeToString(schnorr.SerializePubKey(vtxoPubkey.PubKey())),
		},
	}

	t.Run("private: wrong pkscript in intent rejected", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, map[string]string{})
		// Intent uses a different pubkey's pkscript
		wrongScriptIntent := buildTestIntent(t, testVtxoTxid, testVtxoVout, wrongPkScript, 21000)
		_, err := indexer.GetVirtualTxs(
			context.Background(), "", wrongScriptIntent, testTxids, nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth token or intent")
	})
}

func TestGetVirtualTxs_IntentUnknownVtxo(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	vtxoPubkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := arkscript.P2TRScript(vtxoPubkey.PubKey())
	require.NoError(t, err)

	// Empty vtxo repo — vtxo doesn't exist
	vtxos := map[string]domain.Vtxo{}

	t.Run("private: intent referencing unknown vtxo rejected", func(t *testing.T) {
		indexer := newTestIndexerWithVtxos(t, privkey, "private", vtxos, map[string]string{})
		unknownIntent := buildTestIntent(t, testVtxoTxid, testVtxoVout, pkScript, 21000)
		_, err := indexer.GetVirtualTxs(
			context.Background(), "", unknownIntent, testTxids, nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth token or intent")
	})
}
