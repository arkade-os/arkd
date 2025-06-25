package ports

import (
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type SweepInput interface {
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
	// BuildRoundTx builds a round tx for the given offchain and boarding tx
	// requests. It expects an optional list of connector addresses of expired
	// rounds from which selecting UTXOs as inputs of the transaction.
	// Returns the round tx, the VTXO tree, the connector chain and its root
	// address.
	BuildRoundTx(
		serverPubkey *secp256k1.PublicKey, txRequests domain.TxRequests,
		boardingInputs []BoardingInput, connectorAddresses []string,
		cosigners [][]string,
	) (
		roundTx string,
		vtxoTree *tree.TxGraph,
		connectorAddress string,
		connectors *tree.TxGraph,
		err error,
	)
	// VerifyForfeitTxs verifies a list of forfeit txs against a set of VTXOs and
	// connectors.
	VerifyForfeitTxs(
		vtxos []domain.Vtxo, connectors []tree.TxGraphChunk, txs []string,
	) (valid map[domain.Outpoint]ValidForfeitTx, err error)
	BuildSweepTx(inputs []SweepInput) (txid string, signedSweepTx string, err error)
	GetSweepInput(graph *tree.TxGraph) (vtxoTreeExpiry *common.RelativeLocktime, sweepInput SweepInput, err error)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyTapscriptPartialSigs(tx string) (valid bool, txid string, err error)
	VerifyAndCombinePartialTx(dest string, src string) (string, error)
	CountSignedTaprootInputs(tx string) (int, error)
	GetTxID(tx string) (string, error)
}
