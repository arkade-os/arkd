package txbuilder

import (
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func getOnchainOutputs(
	intents []domain.Intent, network *chaincfg.Params,
) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0)
	for _, intent := range intents {
		for _, receiver := range intent.Receivers {
			if receiver.IsOnchain() {
				receiverAddr, err := btcutil.DecodeAddress(receiver.OnchainAddress, network)
				if err != nil {
					return nil, err
				}

				receiverScript, err := txscript.PayToAddrScript(receiverAddr)
				if err != nil {
					return nil, err
				}

				outputs = append(outputs, &wire.TxOut{
					Value:    int64(receiver.Amount),
					PkScript: receiverScript,
				})
			}
		}
	}
	return outputs, nil
}

func getOutputVtxosLeaves(
	intents []domain.Intent, cosignersPublicKeys [][]string,
) ([]tree.Leaf, error) {
	if len(cosignersPublicKeys) != len(intents) {
		return nil, fmt.Errorf(
			"cosigners public keys length %d does not match intents length %d",
			len(cosignersPublicKeys), len(intents),
		)
	}

	leaves := make([]tree.Leaf, 0)
	for i, intent := range intents {
		leafOutputs := make([]tree.LeafOutput, 0)

		for _, receiver := range intent.Receivers {
			if !receiver.IsOnchain() {
				pubkeyBytes, err := hex.DecodeString(receiver.PubKey)
				if err != nil {
					return nil, fmt.Errorf("failed to decode pubkey: %s", err)
				}

				pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse pubkey: %s", err)
				}

				vtxoScript, err := script.P2TRScript(pubkey)
				if err != nil {
					return nil, fmt.Errorf("failed to create script: %s", err)
				}

				leafOutputs = append(leafOutputs, tree.LeafOutput{
					Amount: receiver.Amount,
					Script: hex.EncodeToString(vtxoScript),
				})
			}
		}

		if len(intent.LeafTxPacket) > 0 {
			assetPacket, err := asset.NewPacketFromString(intent.LeafTxPacket)
			if err != nil {
				return nil, fmt.Errorf("failed to parse asset packet: %s", err)
			}
			assetPacketOut, err := assetPacket.TxOut()
			if err != nil {
				return nil, fmt.Errorf("failed to get asset packet output: %s", err)
			}
			leafOutputs = append(leafOutputs, tree.LeafOutput{
				Amount: uint64(assetPacketOut.Value),
				Script: hex.EncodeToString(assetPacketOut.PkScript),
			})
		}

		leaves = append(leaves, tree.Leaf{
			Outputs:             leafOutputs,
			CosignersPublicKeys: cosignersPublicKeys[i],
		})
	}

	return leaves, nil
}
