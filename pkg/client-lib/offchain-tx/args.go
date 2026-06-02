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

// SendArgs configures the Send orchestrator. It carries the Client used to
// submit and finalize the tx plus every input needed to build it: ServerInfo,
// SignTx, the Vtxos to spend, the change address and the payment Receivers.
type SendArgs struct {
	Client     clientlib.Client
	ServerInfo clientlib.Info
	SignTx     clientlib.SignFn
	Vtxos      []clientlib.Vtxo
	ChangeAddr string
	Receivers  []clientlib.Receiver
}

func (a SendArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	buildArgs := a.toBuildArgs()
	return buildArgs.validate()
}

func (a SendArgs) toBuildArgs() BuildAndSignTxArgs {
	return BuildAndSignTxArgs{
		BaseArgs: BaseArgs{
			ServerInfo: a.ServerInfo,
			SignTx:     a.SignTx,
			Vtxos:      a.Vtxos,
			ChangeAddr: a.ChangeAddr,
		},
		Receivers: a.Receivers,
	}
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

// IssueAssetArgs configures the IssueAsset orchestrator. It carries the Client
// used to submit and finalize the tx plus every input needed to build it:
// ServerInfo, SignTx, the Vtxos to spend, the change address, the Amount of the
// new asset to issue, the optional ControlAsset and the asset Metadata. See
// BuildAndSignIssuanceTxArgs for the ControlAsset semantics.
type IssueAssetArgs struct {
	Client       clientlib.Client
	ServerInfo   clientlib.Info
	SignTx       clientlib.SignFn
	Vtxos        []clientlib.Vtxo
	ChangeAddr   string
	Amount       uint64
	ControlAsset clientlib.ControlAsset
	Metadata     []asset.Metadata
}

func (a IssueAssetArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	buildArgs := a.toBuildArgs()
	return buildArgs.validate()
}

func (a IssueAssetArgs) toBuildArgs() BuildAndSignIssuanceTxArgs {
	return BuildAndSignIssuanceTxArgs{
		BaseArgs: BaseArgs{
			ServerInfo: a.ServerInfo,
			SignTx:     a.SignTx,
			Vtxos:      a.Vtxos,
			ChangeAddr: a.ChangeAddr,
		},
		Amount:       a.Amount,
		ControlAsset: a.ControlAsset,
		Metadata:     a.Metadata,
	}
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
		return fmt.Errorf("missing control asset amount")
	}
	return nil
}

// ReissueAssetArgs configures the ReissueAsset orchestrator. It carries the
// Client used to submit and finalize the tx plus every input needed to build
// it: ServerInfo, SignTx, the Vtxos to spend, the change address, the Asset to
// mint more of and the ControlAsset that authorizes the reissuance. See
// BuildAndSignReissuanceTxArgs for the Asset/ControlAsset semantics.
type ReissueAssetArgs struct {
	Client       clientlib.Client
	ServerInfo   clientlib.Info
	SignTx       clientlib.SignFn
	Vtxos        []clientlib.Vtxo
	ChangeAddr   string
	Asset        clientlib.Asset
	ControlAsset clientlib.Asset
}

func (a ReissueAssetArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	buildArgs := a.toBuildArgs()
	return buildArgs.validate()
}

func (a ReissueAssetArgs) toBuildArgs() BuildAndSignReissuanceTxArgs {
	return BuildAndSignReissuanceTxArgs{
		BaseArgs: BaseArgs{
			ServerInfo: a.ServerInfo,
			SignTx:     a.SignTx,
			Vtxos:      a.Vtxos,
			ChangeAddr: a.ChangeAddr,
		},
		Asset:        a.Asset,
		ControlAsset: a.ControlAsset,
	}
}

// BuildAndSignBurnTxArgs configures the BuildAndSignBurnTx primitive: which
// asset to destroy (AssetId) and how much of it (Amount). Any remaining
// balance is returned to the caller's change address.
type BuildAndSignBurnTxArgs struct {
	BaseArgs
	Asset clientlib.Asset
}

func (a BuildAndSignBurnTxArgs) validate() error {
	if err := a.validateBase(); err != nil {
		return err
	}
	if len(a.Asset.AssetId) <= 0 {
		return fmt.Errorf("missing asset id")
	}
	if a.Asset.Amount == 0 {
		return fmt.Errorf("amount must be > 0")
	}
	return nil
}

// BurnAssetArgs configures the BurnAsset orchestrator. It carries the Client
// used to submit and finalize the tx plus every input needed to build it:
// ServerInfo, SignTx, the Vtxos to spend, the change address and the Asset to
// destroy. See BuildAndSignBurnTxArgs for the Asset semantics.
type BurnAssetArgs struct {
	Client     clientlib.Client
	ServerInfo clientlib.Info
	SignTx     clientlib.SignFn
	Vtxos      []clientlib.Vtxo
	ChangeAddr string
	Asset      clientlib.Asset
}

func (a BurnAssetArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	buildArgs := a.toBuildArgs()
	return buildArgs.validate()
}

func (a BurnAssetArgs) toBuildArgs() BuildAndSignBurnTxArgs {
	return BuildAndSignBurnTxArgs{
		BaseArgs: BaseArgs{
			ServerInfo: a.ServerInfo,
			SignTx:     a.SignTx,
			Vtxos:      a.Vtxos,
			ChangeAddr: a.ChangeAddr,
		},
		Asset: a.Asset,
	}
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
	for _, v := range a.Vtxos {
		if v.IsRecoverable() {
			return fmt.Errorf("invalid funds: vtxo %s is recoverable", v.String())
		}
		if v.Spent {
			return fmt.Errorf("invalid funds: vtxo %s is spent", v.String())
		}
		if v.Unrolled {
			return fmt.Errorf("invalid funds: vtxo %s is unrolled", v.String())
		}
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
