package unroll

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lntypes"
)

func computeVSize(tx *wire.MsgTx) lntypes.VByte {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize() // including witness
	weight := totalSize + baseSize*3
	return lntypes.WeightUnit(uint64(weight)).ToVB()
}

func toOutputScript(onchainAddress string, network arklib.Network) ([]byte, error) {
	netParams := clientlib.ToBitcoinNetwork(network)
	rcvAddr, err := btcutil.DecodeAddress(onchainAddress, &netParams)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(rcvAddr)
}

func addInputs(updater *psbt.Updater, utxos []clientlib.Utxo) error {
	for _, utxo := range utxos {
		vtxoScript, err := script.ParseVtxoScript(utxo.Tapscripts)
		if err != nil {
			return err
		}

		previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return err
		}

		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		pkScript, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return err
		}

		updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *previousHash,
				Index: utxo.VOut,
			},
			Sequence: sequence,
		})

		exitClosures := vtxoScript.ExitClosures()
		if len(exitClosures) <= 0 {
			return fmt.Errorf("no exit closures found")
		}

		exitClosure := exitClosures[0]

		exitScript, err := exitClosure.Script()
		if err != nil {
			return err
		}

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return err
		}

		exitLeaf := txscript.NewBaseTapLeaf(exitScript)
		leafProof, err := taprootTree.GetTaprootMerkleProof(exitLeaf.TapHash())
		if err != nil {
			return fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value:    int64(utxo.Amount),
				PkScript: pkScript,
			},
			TaprootLeafScript: []*psbt.TaprootTapLeafScript{
				{
					ControlBlock: leafProof.ControlBlock,
					Script:       leafProof.Script,
					LeafVersion:  txscript.BaseLeafVersion,
				},
			},
		})
	}

	return nil
}

func getMatureUtxos(
	ctx context.Context,
	explorer clientlib.Explorer,
	arkAddr clientlib.Address,
	network arklib.Network,
) ([]clientlib.Utxo, error) {
	rawScript, err := arkAddr.RawScript()
	if err != nil {
		return nil, err
	}

	signingClosure, err := arkAddr.ExitClosure()
	if err != nil {
		return nil, err
	}

	exitDelay, err := rawScript.SmallestExitDelay()
	if err != nil {
		return nil, err
	}

	now := time.Now()

	addrTapscripts := make(map[string][]string)
	// nolint
	script, _ := toOutputScript(arkAddr.Address, network)
	addrTapscripts[hex.EncodeToString(script)] = arkAddr.Tapscripts

	fetchedUtxos, err := explorer.GetUtxos([]string{arkAddr.Address})
	if err != nil {
		return nil, err
	}

	utxos := make([]clientlib.Utxo, 0)
	for _, utxo := range fetchedUtxos {
		tapscripts := addrTapscripts[utxo.Script]
		u := utxo.ToUtxo(*exitDelay, tapscripts, signingClosure)
		if u.RedeemableAt.Before(now) {
			utxos = append(utxos, u)
		}
	}
	return utxos, nil
}

func getBranchesToUnroll(
	ctx context.Context,
	explorer clientlib.Explorer,
	indexer clientlib.Indexer,
	vtxos []clientlib.Vtxo,
) (map[string]*RedeemBranch, error) {
	redeemBranches := make(map[string]*RedeemBranch, 0)

	for _, vtxo := range vtxos {
		redeemBranch, err := NewRedeemBranch(ctx, explorer, indexer, vtxo)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}
