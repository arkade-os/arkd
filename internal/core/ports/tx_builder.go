package ports

import (
	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type SweepableOutput struct {
	Amount int64
	Hash   chainhash.Hash
	Index  uint32
	// Script is the tapscript that should be used to sweep the output
	Script []byte
	// ControlBlock is the control block associated with leaf script
	ControlBlock []byte
	// InternalKey is the internal key used to compute the control block
	InternalKey *btcec.PublicKey
}

type Input struct {
	domain.Outpoint
	Tapscripts []string
}

type BoardingInput struct {
	Input
	Amount uint64
}

type ValidForfeitTx struct {
	Tx        string
	Connector domain.Outpoint
}

type TxBuilder interface {
	// BuildCommitmentTx builds a commitment tx for the given intents and boarding inputs
	// It expects an optional list of connector addresses of expired batches from which selecting
	// utxos as inputs of the transaction.
	// Returns the commitment tx, the vtxo tree, the connector tree and its root address.
	BuildCommitmentTx(
		signerPubkey *btcec.PublicKey, intents domain.Intents,
		boardingInputs []BoardingInput, connectorAddresses []string,
		cosigners [][]string,
	) (
		commitmentTx string, vtxoTree *tree.TxTree,
		connectorAddress string, connectors *tree.TxTree, err error,
	)
	// VerifyForfeitTxs verifies a list of forfeit txs against a set of VTXOs and
	// connectors.
	VerifyForfeitTxs(
		vtxos []domain.Vtxo, connectors tree.FlatTxTree, txs []string,
	) (valid map[domain.Outpoint]ValidForfeitTx, err error)
	BuildSweepTx(inputs []SweepableOutput) (txid string, signedSweepTx string, err error)
	GetSweepableBatchOutputs(vtxoTree *tree.TxTree) (
		vtxoTreeExpiry *arklib.RelativeLocktime, batchOutputs SweepableOutput, err error,
	)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyTapscriptPartialSigs(tx string) (valid bool, ptx *psbt.Packet, err error)
	VerifyAndCombinePartialTx(dest string, src string) (string, error)
	CountSignedTaprootInputs(tx string) (int, error)
}
