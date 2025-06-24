package redemption

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type CovenantlessRedeemBranch struct {
	vtxo           types.Vtxo
	branch         []*psbt.Packet
	vtxoTreeExpiry time.Duration
	explorer       explorer.Explorer
}

func NewRedeemBranch(
	explorer explorer.Explorer,
	graph *tree.TxGraph, vtxo types.Vtxo,
) (*CovenantlessRedeemBranch, error) {
	vtxoTreeExpiry, err := tree.GetVtxoTreeExpiry(graph.Root.Inputs[0])
	if err != nil {
		return nil, err
	}

	subGraph, err := graph.SubGraph([]string{vtxo.Txid})
	if err != nil {
		return nil, err
	}

	branch := make([]*psbt.Packet, 0)
	_ = subGraph.Apply(func(g *tree.TxGraph) (bool, error) {
		branch = append(branch, g.Root)
		return true, nil
	})

	return &CovenantlessRedeemBranch{
		vtxo:           vtxo,
		branch:         branch,
		vtxoTreeExpiry: time.Duration(vtxoTreeExpiry.Seconds()) * time.Second,
		explorer:       explorer,
	}, nil
}

// RedeemPath returns the list of transactions to broadcast in order to access the vtxo output
func (r *CovenantlessRedeemBranch) RedeemPath() ([]string, error) {
	transactions := make([]string, 0, len(r.branch))

	offchainPath, err := r.OffchainPath()
	if err != nil {
		return nil, err
	}

	for _, ptx := range offchainPath {
		firstInput := ptx.Inputs[0]
		if len(firstInput.TaprootKeySpendSig) == 0 {
			return nil, fmt.Errorf("missing taproot key spend signature")
		}

		var witness bytes.Buffer

		if err := psbt.WriteTxWitness(&witness, [][]byte{firstInput.TaprootKeySpendSig}); err != nil {
			return nil, err
		}

		ptx.Inputs[0].FinalScriptWitness = witness.Bytes()

		extracted, err := psbt.Extract(ptx)
		if err != nil {
			return nil, err
		}

		var txBytes bytes.Buffer

		if err := extracted.Serialize(&txBytes); err != nil {
			return nil, err
		}

		transactions = append(transactions, hex.EncodeToString(txBytes.Bytes()))
	}

	return transactions, nil
}

func (r *CovenantlessRedeemBranch) ExpiresAt() (*time.Time, error) {
	lastKnownBlocktime := int64(0)

	var confirmed bool
	blocktime := int64(math.MaxInt64)
	for _, txid := range r.vtxo.CommitmentTxids {
		rConfirmed, rBlocktime, _ := r.explorer.GetTxBlockTime(txid)
		if confirmed && rBlocktime < blocktime {
			blocktime = rBlocktime
			confirmed = rConfirmed
		}
	}

	if confirmed {
		lastKnownBlocktime = blocktime
	} else {
		expirationFromNow := time.Now().Add(time.Minute).Add(r.vtxoTreeExpiry)
		return &expirationFromNow, nil
	}

	for _, ptx := range r.branch {
		txid := ptx.UnsignedTx.TxID()

		confirmed, blocktime, err := r.explorer.GetTxBlockTime(txid)
		if err != nil {
			break
		}

		if confirmed {
			lastKnownBlocktime = blocktime
			continue
		}

		break
	}

	t := time.Unix(lastKnownBlocktime, 0).Add(r.vtxoTreeExpiry)
	return &t, nil
}

// OffchainPath checks for transactions of the branch onchain and returns only the offchain part
func (r *CovenantlessRedeemBranch) OffchainPath() ([]*psbt.Packet, error) {
	offchainPath := append([]*psbt.Packet{}, r.branch...)

	for i := len(r.branch) - 1; i >= 0; i-- {
		ptx := r.branch[i]
		txHash := ptx.UnsignedTx.TxID()

		confirmed, _, err := r.explorer.GetTxBlockTime(txHash)

		// if the tx is not found, it's offchain, let's continue
		if err != nil {
			continue
		}

		// if found but not confirmed, it means the tx is in the mempool
		// an unilateral exit is running, we must wait for it to be confirmed
		if !confirmed {
			return nil, ErrPendingConfirmation{Txid: txHash}
		}

		// if no error, the tx exists onchain, so we can remove it (+ the parents) from the branch
		if i == len(r.branch)-1 {
			offchainPath = []*psbt.Packet{}
		} else {
			offchainPath = r.branch[i+1:]
		}

		break
	}

	return offchainPath, nil
}

// ErrPendingConfirmation is returned when computing the offchain path of a redeem branch. Due to P2A relay policy, only 1C1P packages are accepted.
// This error is returned when the tx is found onchain but not confirmed yet, allowing the user to know when to wait for the tx to be confirmed or to continue with the redemption.
type ErrPendingConfirmation struct {
	Txid string
}

func (e ErrPendingConfirmation) Error() string {
	return fmt.Sprintf("unilateral exit is running, please wait for tx %s to be confirmed", e.Txid)
}
