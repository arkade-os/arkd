package offchaintx

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
)

// BuildAndSignTxArgs configures the BuildAndSignTx primitive. Receivers are
// the outputs of the offchain payment; the rest of the configuration comes
// from BaseArgs (server info, vtxos to spend, change address, SignTx).
type BuildAndSignTxArgs struct {
	BaseArgs
	Receivers []clientlib.Receiver
}

func (a *BuildAndSignTxArgs) validate() error {
	if err := a.validateBase(); err != nil {
		return err
	}
	if len(a.Receivers) == 0 {
		return fmt.Errorf("missing receivers")
	}
	return nil
}

// SendArgs configures the Send orchestrator: the same inputs as
// BuildAndSignTxArgs plus a Client used to submit and finalize the tx.
type SendArgs struct {
	BuildAndSignTxArgs
	Client clientlib.Client
}

func (a SendArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	return a.BuildAndSignTxArgs.validate()
}

// BuildAndSignIssuanceTxArgs configures the BuildAndSignIssuanceTx primitive.
// Amount is the quantity of the new asset to issue. ControlAsset is optional:
// pass NewControlAsset to mint a fresh control asset alongside the issuance,
// ExistingControlAsset to authorize via a control asset already held, or nil
// for an unauthorized issuance. Metadata is attached to the new asset group.
type BuildAndSignIssuanceTxArgs struct {
	BaseArgs
	Amount       uint64
	ControlAsset clientlib.ControlAsset
	Metadata     []asset.Metadata
}

func (a BuildAndSignIssuanceTxArgs) validate() error {
	if err := a.validateBase(); err != nil {
		return err
	}
	if a.Amount == 0 {
		return fmt.Errorf("amount must be > 0")
	}
	return nil
}

// IssueAssetArgs configures the IssueAsset orchestrator: the same inputs as
// BuildAndSignIssuanceTxArgs plus a Client used to submit and finalize the tx.
type IssueAssetArgs struct {
	BuildAndSignIssuanceTxArgs
	Client clientlib.Client
}

func (a IssueAssetArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	return a.BuildAndSignIssuanceTxArgs.validate()
}

// BuildAndSignReissuanceTxArgs configures the BuildAndSignReissuanceTx
// primitive. AssetId is the existing asset to mint more of; ControlAssetId
// identifies the control asset that authorizes the reissuance (caller is
// expected to resolve it from the indexer); Amount is the quantity to mint.
type BuildAndSignReissuanceTxArgs struct {
	BaseArgs
	Asset        clientlib.Asset
	ControlAsset clientlib.Asset
}

func (a BuildAndSignReissuanceTxArgs) validate() error {
	if err := a.validateBase(); err != nil {
		return err
	}
	if len(a.Asset.AssetId) <= 0 {
		return fmt.Errorf("missing asset id")
	}
	if a.Asset.Amount == 0 {
		return fmt.Errorf("missing asset amount")
	}
	if len(a.ControlAsset.AssetId) <= 0 {
		return fmt.Errorf("missing control asset id")
	}
	if a.ControlAsset.Amount == 0 {
		return fmt.Errorf("missing control assset amount")
	}
	return nil
}

// ReissueAssetArgs configures the ReissueAsset orchestrator: the same inputs
// as BuildAndSignReissuanceTxArgs plus a Client used to submit and finalize
// the tx.
type ReissueAssetArgs struct {
	BuildAndSignReissuanceTxArgs
	Client clientlib.Client
}

func (a ReissueAssetArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	return a.BuildAndSignReissuanceTxArgs.validate()
}

// BuildAndSignBurnTxArgs configures the BuildAndSignBurnTx primitive: which
// asset to destroy (AssetId) and how much of it (Amount). Any remaining
// balance is returned to the caller's change address.
type BuildAndSignBurnTxArgs struct {
	BaseArgs
	AssetId string
	Amount  uint64
}

func (a BuildAndSignBurnTxArgs) validate() error {
	if err := a.validateBase(); err != nil {
		return err
	}
	if a.AssetId == "" {
		return fmt.Errorf("missing asset id")
	}
	if a.Amount == 0 {
		return fmt.Errorf("amount must be > 0")
	}
	return nil
}

// BurnAssetArgs configures the BurnAsset orchestrator: the same inputs as
// BuildAndSignBurnTxArgs plus a Client used to submit and finalize the tx.
type BurnAssetArgs struct {
	BuildAndSignBurnTxArgs
	Client clientlib.Client
}

func (a BurnAssetArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	return a.BuildAndSignBurnTxArgs.validate()
}

// FinalizePendingTxsArgs configures the FinalizePendingTxs orchestrator.
// Vtxos lists the pending vtxos whose pending offchain txs should be
// fetched, signed, and finalized; the caller has already filtered them.
// CreatedAfter is informational only — used by the caller to track which
// txs were considered.
type FinalizePendingTxsArgs struct {
	Client       clientlib.Client
	SignTx       clientlib.SignFn
	Vtxos        []clientlib.Vtxo
	CreatedAfter *time.Time // informational only; caller already filtered Vtxos
}

func (a FinalizePendingTxsArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx")
	}
	if len(a.Vtxos) == 0 {
		return fmt.Errorf("missing vtxos")
	}
	return nil
}

// BaseArgs is the input shared by every BuildAndSign...Tx primitive
// and the orchestrators that wrap them.
type BaseArgs struct {
	ServerInfo clientlib.Info   // provides Dust, SignerPubKey (hex), CheckpointTapscript (hex)
	SignTx     clientlib.SignFn // signs ark tx + checkpoint txs
	Vtxos      []clientlib.Vtxo // pre-fetched spendable vtxos (selection runs inside the primitive)
	ChangeAddr string           // pre-derived offchain change address

	signerPubkey        *btcec.PublicKey
	checkpointTapscript []byte
}

func (a *BaseArgs) validateBase() error {
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx")
	}
	if a.ServerInfo.Dust == 0 {
		return fmt.Errorf("missing server info")
	}
	if a.ServerInfo.SignerPubKey == "" {
		return fmt.Errorf("missing signer pubkey")
	}
	if a.ChangeAddr == "" {
		return fmt.Errorf("missing change address")
	}
	signerPubkey, err := parsePubkey(a.ServerInfo.SignerPubKey)
	if err != nil {
		return fmt.Errorf("invalid signer pubkey: %w", err)
	}
	a.signerPubkey = signerPubkey
	return nil
}

func (a *BaseArgs) signerPubKey() (*btcec.PublicKey, error) {
	if a.signerPubkey != nil {
		return a.signerPubkey, nil
	}

	signerPubkey, err := parsePubkey(a.ServerInfo.SignerPubKey)
	if err != nil {
		return nil, err
	}
	a.signerPubkey = signerPubkey
	return signerPubkey, nil
}

func (a *BaseArgs) checkpointExitPath() ([]byte, error) {
	if len(a.checkpointTapscript) > 0 {
		return a.checkpointTapscript, nil
	}

	if len(a.ServerInfo.CheckpointTapscript) <= 0 {
		return nil, fmt.Errorf("missing checkpoint tapscript")
	}
	buf, err := hex.DecodeString(a.ServerInfo.CheckpointTapscript)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid checkpoint tapscript format: expected hex, got %s",
			a.ServerInfo.CheckpointTapscript,
		)
	}
	a.checkpointTapscript = buf
	return buf, nil
}
