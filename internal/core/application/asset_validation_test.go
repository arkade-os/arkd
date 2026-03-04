package application

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// mockAssetRepository is a minimal stub that satisfies domain.AssetRepository
// for unit-testing validateAssetTransaction. None of the methods should be
// reached in the test scenarios below.
type mockAssetRepository struct{}

func (m mockAssetRepository) AddAssets(
	_ context.Context,
	_ map[string][]domain.Asset,
) (int, error) {
	return 0, nil
}

func (m mockAssetRepository) GetAssets(_ context.Context, _ []string) ([]domain.Asset, error) {
	return nil, nil
}

func (m mockAssetRepository) GetControlAsset(_ context.Context, _ string) (string, error) {
	return "", nil
}

func (m mockAssetRepository) AssetExists(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (m mockAssetRepository) Close() {}

// mockRepoManager is the minimal stub that provides the Assets() repository
// needed by the assetSource wrapper inside validateAssetTransaction.
type mockRepoManager struct {
	assets domain.AssetRepository
}

func (m mockRepoManager) Events() domain.EventRepository                { return nil }
func (m mockRepoManager) Rounds() domain.RoundRepository                { return nil }
func (m mockRepoManager) Vtxos() domain.VtxoRepository                  { return nil }
func (m mockRepoManager) ScheduledSession() domain.ScheduledSessionRepo { return nil }
func (m mockRepoManager) OffchainTxs() domain.OffchainTxRepository      { return nil }
func (m mockRepoManager) Convictions() domain.ConvictionRepository      { return nil }
func (m mockRepoManager) Assets() domain.AssetRepository                { return m.assets }
func (m mockRepoManager) Fees() domain.FeeRepository                    { return nil }
func (m mockRepoManager) Close()                                        {}

// newTestService creates a minimal *service instance with only the fields
// needed by validateAssetTransaction.
func newTestService() *service {
	return &service{
		repoManager:      mockRepoManager{assets: mockAssetRepository{}},
		maxAssetsPerVtxo: 10,
	}
}

// txWithoutAssetPacket builds a wire.MsgTx that has one standard P2TR output
// but no OP_RETURN asset packet.
func txWithoutAssetPacket() *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	// Add a dummy input (prevout).
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0},
	})
	// Add a standard (non-OP_RETURN) output.
	tx.AddTxOut(&wire.TxOut{
		Value: 1000,
		PkScript: []byte{
			0x51,
			0x20,
			0x01,
			0x02,
			0x03,
			0x04,
			0x05,
			0x06,
			0x07,
			0x08,
			0x09,
			0x0a,
			0x0b,
			0x0c,
			0x0d,
			0x0e,
			0x0f,
			0x10,
			0x11,
			0x12,
			0x13,
			0x14,
			0x15,
			0x16,
			0x17,
			0x18,
			0x19,
			0x1a,
			0x1b,
			0x1c,
			0x1d,
			0x1e,
			0x1f,
			0x20,
		},
	})
	return tx
}

// txWithInvalidAssetPacket builds a wire.MsgTx together with an
// extension.Extension whose asset packet references an output index (vout=99)
// that does not exist in the transaction. This triggers an
// ASSET_OUTPUT_INVALID error during validateAssetTransaction, which must NOT
// be suppressed by the ignoreMissingAssetPackets flag.
func txWithInvalidAssetPacket(t *testing.T) (*wire.MsgTx, extension.Extension) {
	t.Helper()

	// Build an asset packet with one issuance group whose output points to
	// vout=99 (well beyond the transaction's actual output count).
	packet := asset.Packet{
		{
			AssetId: nil, // issuance
			Outputs: []asset.AssetOutput{
				{Type: asset.AssetOutputTypeLocal, Vout: 99, Amount: 100},
			},
			Inputs: []asset.AssetInput{},
		},
	}

	ext := extension.Extension{packet}

	// Serialize the extension into an OP_RETURN output so that
	// ValidateAssetTransaction's "packet found in tx" check passes.
	extTxOut, err := ext.TxOut()
	require.NoError(t, err, "extension.TxOut() should succeed")

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0},
	})
	tx.AddTxOut(extTxOut)
	// Add a standard P2TR output so the tx isn't degenerate.
	tx.AddTxOut(&wire.TxOut{
		Value: 1000,
		PkScript: []byte{
			0x51, 0x20,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		},
	})
	return tx, ext
}

// nonEmptyAssetInputs returns an inputAssets map with a single dummy entry,
// simulating a transaction that spends an asset-carrying VTXO.
func nonEmptyAssetInputs() map[int][]domain.AssetDenomination {
	return map[int][]domain.AssetDenomination{
		0: {{AssetId: "aabbccdd", Amount: 100}},
	}
}

func TestValidateAssetTransaction_FlagTrue_MissingPacket(t *testing.T) {
	// When ignoreMissingAssetPackets=true and the transaction has asset inputs
	// but no OP_RETURN asset packet, the "asset packet not found"
	// ASSET_VALIDATION_FAILED error should be suppressed (return nil).
	svc := newTestService()
	tx := txWithoutAssetPacket()
	inputs := nonEmptyAssetInputs()

	err := svc.validateAssetTransaction(context.Background(), tx, extension.Extension{}, inputs, true)
	require.NoError(t, err,
		"flag=true should suppress 'asset packet not found' error")
}

func TestValidateAssetTransaction_FlagFalse_MissingPacket(t *testing.T) {
	// When ignoreMissingAssetPackets=false and the transaction has asset inputs
	// but no OP_RETURN asset packet, the error should be propagated as
	// ASSET_VALIDATION_FAILED with "asset packet not found" in the message.
	svc := newTestService()
	tx := txWithoutAssetPacket()
	inputs := nonEmptyAssetInputs()

	err := svc.validateAssetTransaction(context.Background(), tx, extension.Extension{}, inputs, false)
	require.Error(t, err, "flag=false should propagate missing-packet error")
	require.Equal(t, "ASSET_VALIDATION_FAILED", err.CodeName(),
		"error should have ASSET_VALIDATION_FAILED code")
	require.Contains(t, err.Error(), "asset packet not found",
		"error message should contain 'asset packet not found'")
}

func TestValidateAssetTransaction_FlagTrue_OtherAssetError(t *testing.T) {
	// When ignoreMissingAssetPackets=true and the extension carries a valid
	// asset packet that causes a validation error OTHER than "asset packet not
	// found" (e.g. an output index out of range), the error must NOT be
	// suppressed. Only the specific "asset packet not found" branch is silenced
	// by the flag.
	svc := newTestService()
	tx, ext := txWithInvalidAssetPacket(t)
	inputs := nonEmptyAssetInputs()

	err := svc.validateAssetTransaction(context.Background(), tx, ext, inputs, true)
	require.Error(t, err,
		"flag=true should NOT suppress non-'not found' asset validation errors")
	require.NotContains(t, err.Error(), "asset packet not found",
		"error should be a different asset validation error, not 'not found'")
	require.Contains(t, err.Error(), "not present in the packet",
		"error should indicate asset input mismatch with the packet")
}
