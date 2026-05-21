package batchsession

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// BatchTxRes is the result of a completed batch session. CommitmentTxid and
// CommitmentTx identify the on-chain commitment transaction the server
// broadcasts; IntentTx is the signed intent proof PSBT that registered this
// participant; ForfeitTxs are the signed forfeit transactions for spent vtxos;
// VtxoInputs / UtxoInputs record the consumed inputs and VtxoOutputs /
// UtxoOutputs the produced offchain vtxos and on-chain receivers. Extension
// carries any asset packet attached to the batch.
type BatchTxRes struct {
	CommitmentTxid string
	CommitmentTx   string
	IntentTx       string
	ForfeitTxs     []string
	VtxoInputs     []clientlib.Vtxo
	UtxoInputs     []clientlib.Utxo
	VtxoOutputs    []clientlib.Vtxo
	UtxoOutputs    []clientlib.Receiver
	Extension      extension.Extension
}

// JoinBatchArgs configures a JoinBatch call: the funds to consume
// (Notes/Vtxos/BoardingUtxos from BaseArgs), the desired Outputs, the SignTx
// callback used to sign the intent proof and ark-side artifacts, plus the
// Client used to talk to the server and the cached ServerInfo.
type JoinBatchArgs struct {
	BaseArgs
	TreeSigners []tree.SignerSession
	IntentId    string
	Client      clientlib.Client
	ServerInfo  clientlib.Info
}

func (a JoinBatchArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	if len(a.Notes) <= 0 && len(a.Vtxos) <= 0 && len(a.BoardingUtxos) <= 0 {
		return fmt.Errorf("missing funds to join a batch")
	}
	if len(a.Outputs) <= 0 {
		return fmt.Errorf("missing outputs")
	}
	if a.IntentId == "" {
		return fmt.Errorf("missing intent id")
	}
	if a.signingRequired() && len(a.TreeSigners) <= 0 {
		return fmt.Errorf("missing tree signer(s)")
	}
	return nil
}

// IntentArgs configures the BuildAndSign*Intent primitives (Register, Delete,
// GetPendingTx). Cosigners holds the public keys of vtxo-tree signer sessions
// and is only required when registering an intent that will participate in
// tree signing.
type IntentArgs struct {
	BaseArgs
	Cosigners []string
}

func (a IntentArgs) validateForRegister() error {
	if len(a.Vtxos)+len(a.BoardingUtxos)+len(a.Notes) <= 0 {
		return fmt.Errorf("missing funds")
	}
	if len(a.Outputs) <= 0 {
		return fmt.Errorf("missing outputs")
	}
	if len(a.Cosigners) <= 0 {
		return fmt.Errorf("missing cosigners")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx")
	}
	return nil
}

func (a IntentArgs) validateForDelete() error {
	if len(a.Vtxos)+len(a.BoardingUtxos)+len(a.Notes) <= 0 {
		return fmt.Errorf("missing funds")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx")
	}
	return nil
}

func (a IntentArgs) validateForGetPendingTx() error {
	if len(a.Vtxos) <= 0 {
		return fmt.Errorf("missing funds")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx")
	}
	return nil
}

func (a IntentArgs) intentInputs() (
	intentInputs []intent.Input, assetInputs map[int][]clientlib.Asset,
	leafProofs []*arklib.TaprootMerkleProof, psbtFields [][]*psbt.Unknown, err error,
) {
	return toIntentInputs(a.BoardingUtxos, a.Vtxos, a.Notes)
}

// BaseArgs groups the inputs and outputs common to all batch-session operations
// (Settle, CollaborativeExit, RedeemNotes, JoinBatch) along with the SignTx
// callback used to sign the intent proof PSBT and any forfeit / commitment
// artifacts produced during the batch.
type BaseArgs struct {
	Notes         []string
	Vtxos         []clientlib.Vtxo
	BoardingUtxos []clientlib.Utxo
	Outputs       []clientlib.Receiver
	SignTx        batchsessionhandler.SignFn
}

func (a BaseArgs) signingRequired() bool {
	return len(a.Vtxos)+len(a.BoardingUtxos) > 0
}
