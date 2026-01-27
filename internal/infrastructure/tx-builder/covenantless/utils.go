package txbuilder

import (
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
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
		cosigners := cosignersPublicKeys[i]

		for _, receiver := range intent.Receivers {
			if receiver.IsOnchain() {
				// Onchain outputs are not part of the vtxo tree.
				continue
			}

			// Decode and parse receiver pubkey once for both asset and non-asset cases.
			pubkeyBytes, err := hex.DecodeString(receiver.PubKey)
			if err != nil {
				return nil, fmt.Errorf("receiver pubkey hex decode failed: %w", err)
			}

			pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
			if err != nil {
				return nil, fmt.Errorf("receiver pubkey parse failed: %w", err)
			}

			vtxoScript, err := script.P2TRScript(pubkey)
			if err != nil {
				return nil, fmt.Errorf("failed to create P2TR script: %w", err)
			}

			leaf := tree.Leaf{
				Script:              hex.EncodeToString(vtxoScript),
				Amount:              receiver.Amount,
				CosignersPublicKeys: cosigners,
			}

			// AssetGroup intent case
			if len(receiver.AssetPacket) > 0 {
				leaf.ExtensionScript = receiver.AssetPacket
			}

			leaves = append(leaves, leaf)
		}
	}
	return leaves, nil
}
