package offchaintx

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

// SignFn signs the provided base64-encoded PSBT with the caller's identity
// and returns the signed PSBT base64.
type SignFn func(ctx context.Context, tx string) (string, error)

// BuildAndSignTxRes is the output of every BuildAndSign...Tx primitive
// except BuildAndSignIssuanceTx (which also adds the derived asset IDs).
type BuildAndSignTxRes struct {
	// Txid of the resulting ark tx, computed from arkPtx.UnsignedTx.TxID()
	// after all outputs (including the extension OP_RETURN) are attached but
	// before any witnesses are added. Witness data does not affect the txid.
	Txid string
	// ArkTx is the unsigned PSBT (base64) used for post-submit verification.
	ArkTx string
	// SignedArkTx is the client-signed PSBT (base64) ready for SubmitTx.
	SignedArkTx string
	// CheckpointTxs are the unsigned checkpoint PSBTs (base64). They are
	// signed by the client only after the server signs them in SubmitTx;
	// finalization passes them through args.SignTx.
	CheckpointTxs  []string
	SelectedCoins  []clientlib.Vtxo
	ChangeReceiver *clientlib.Receiver
	AssetPacket    asset.Packet
	Extension      extension.Extension
}

// BuildAndSignIssuanceTxRes extends BuildAndSignTxRes with the asset IDs derived
// inside the primitive from the unsigned tx's txid plus the asset-group index.
type BuildAndSignIssuanceTxRes struct {
	BuildAndSignTxRes
	IssuedAssets []asset.AssetId
}

// OffchainTxRes is the result of a full-lifecycle orchestrator call.
type OffchainTxRes struct {
	Txid          string
	Tx            string
	CheckpointTxs []string
	Inputs        []clientlib.Vtxo
	Outputs       []clientlib.Receiver
	Extension     extension.Extension
}

// IssueAssetRes carries the new asset IDs alongside the standard offchain
// transaction result.
type IssueAssetRes struct {
	OffchainTxRes
	IssuedAssets []asset.AssetId
}
