package ports

import (
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type SweepableBatchOutput interface {
	GetAmount() uint64
	GetHash() chainhash.Hash
	GetIndex() uint32
	GetLeafScript() []byte
	GetControlBlock() []byte
	GetInternalKey() *secp256k1.PublicKey
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
	// It expects an optional list of connector addresses of expired bacthes from which selecting
	// utxos as inputs of the transaction.
	// Returns the commitment tx, the vtxo tree, the connector tree and its root address.
	BuildCommitmentTx(
		serverPubkey *secp256k1.PublicKey, intents domain.Intents,
		boardingInputs []BoardingInput, connectorAddresses []string,
		cosigners [][]string,
	) (
		commitmentTx string, vtxoTree *tree.TxGraph,
		connectorAddress string, connectors *tree.TxGraph, err error,
	)
	// VerifyForfeitTxs verifies a list of forfeit txs against a set of VTXOs and
	// connectors.
	VerifyForfeitTxs(
		vtxos []domain.Vtxo, connectors []tree.TxGraphChunk, txs []string,
	) (valid map[domain.Outpoint]ValidForfeitTx, err error)
	BuildSweepTx(inputs []SweepableBatchOutput) (txid string, signedSweepTx string, err error)
	GetSweepableBacthOutputs(vtxoTree *tree.TxGraph) (
		vtxoTreeExpiry *common.RelativeLocktime, bacthOutputs SweepableBatchOutput, err error,
	)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyTapscriptPartialSigs(tx string) (valid bool, txid string, err error)
	VerifyAndCombinePartialTx(dest string, src string) (string, error)
	CountSignedTaprootInputs(tx string) (int, error)
}
