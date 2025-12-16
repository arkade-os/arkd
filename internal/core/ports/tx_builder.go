package ports

import (
	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type Input struct {
	domain.Outpoint
	Tapscripts []string
}

func (i Input) OutputScript() ([]byte, error) {
	boardingVtxoScript, err := script.ParseVtxoScript(i.Tapscripts)
	if err != nil {
		return nil, err
	}

	tapKey, _, err := boardingVtxoScript.TapTree()
	if err != nil {
		return nil, err
	}

	return script.P2TRScript(tapKey)
}

type BoardingInput struct {
	Input
	Amount uint64
}

type ValidForfeitTx struct {
	Tx        string
	Connector domain.Outpoint
}

type SignedBoardingInput struct {
	Signatures []*psbt.TaprootScriptSpendSig
	LeafScript *psbt.TaprootTapLeafScript
}

type TxBuilder interface {
	// BuildCommitmentTx builds a commitment tx for the given intents and boarding inputs
	// It expects an optional list of connector addresses of expired batches from which selecting
	// utxos as inputs of the transaction.
	// Returns the commitment tx, the vtxo tree, the connector tree and its root address.
	BuildCommitmentTx(
		signerPubkey *btcec.PublicKey, intents domain.Intents,
		boardingInputs []BoardingInput, cosigners [][]string,
	) (
		commitmentTx string, vtxoTree *tree.TxTree,
		connectorAddress string, connectors *tree.TxTree, err error,
	)
	// VerifyForfeitTxs verifies a list of forfeit txs against a set of VTXOs and
	// connectors.
	VerifyForfeitTxs(
		vtxos []domain.Vtxo, connectors tree.FlatTxTree, txs []string,
	) (valid map[domain.Outpoint]ValidForfeitTx, err error)
	BuildSweepTx(inputs []TxInput) (txid string, signedSweepTx string, err error)
	GetSweepableBatchOutputs(vtxoTree *tree.TxTree) (
		vtxoTreeExpiry *arklib.RelativeLocktime, batchOutputs TxInput, err error,
	)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyVtxoTapscriptSigs(
		tx string, mustIncludeSignerSig bool,
	) (valid bool, ptx *psbt.Packet, err error)
	VerifyBoardingTapscriptSigs(
		signedTx string, commitmentTx string,
	) (map[uint32]SignedBoardingInput, error)
}
