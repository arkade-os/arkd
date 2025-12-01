package txbuilder

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
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
	intents []domain.Intent, forfeitPubkey *btcec.PublicKey, signingPubkey *btcec.PublicKey, unilateralExitDelay arklib.RelativeLocktime, cosignersPublicKeys [][]string,
) ([]tree.Leaf, error) {
	if len(cosignersPublicKeys) != len(intents) {
		return nil, fmt.Errorf(
			"cosigners public keys length %d does not match intents length %d",
			len(cosignersPublicKeys), len(intents),
		)
	}

	leaves := make([]tree.Leaf, 0)
	for i, intent := range intents {
		for _, receiver := range intent.Receivers {
			if !receiver.IsOnchain() {
				// TODO (Joshua): ensure the Teleport Hash is being used correctly and that Asset data is restored
				if len(receiver.AssetId) > 0 {
					pubkeyBytes, err := hex.DecodeString(receiver.PubKey)
					if err != nil {
						return nil, fmt.Errorf("failed to decode pubkey: %s", err)
					}

					// reconstruct the asset teleport pubkey and ensure they match
					hash, err := hex.DecodeString(receiver.AssetTeleportHash)
					if err != nil {
						return nil, fmt.Errorf("failed to decode teleport hash: %s", err)
					}

					ownerPubkeyBytes, err := hex.DecodeString(receiver.AssetTeleportPubkey)
					if err != nil {
						return nil, fmt.Errorf("failed to decode teleport pubkey: %s", err)
					}

					ownerPubkey, err := schnorr.ParsePubKey(ownerPubkeyBytes)
					if err != nil {
						return nil, fmt.Errorf("failed to parse teleport pubkey: %s", err)
					}

					teleportScript := script.NewTeleportVtxoScript(ownerPubkey, signingPubkey, hash, unilateralExitDelay)

					teleportKey, _, err := teleportScript.TapTree()
					if err != nil {
						return nil, fmt.Errorf("failed to get teleport taproot key: %s", err)
					}

					encodedTeleportPubkey := schnorr.SerializePubKey(teleportKey)

					// TODO (Joshua) rectify compare the reconstructed teleport pubkey with the provided pubkey
					if !bytes.Equal(encodedTeleportPubkey, pubkeyBytes) {
						log.Println("This does not add up")
						// return nil, fmt.Errorf("asset teleport pubkey does not match reconstructed pubkey")
					}

					// get pubkey bytes
					pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
					if err != nil {
						return nil, fmt.Errorf("failed to parse pubkey: %s", err)
					}

					assetIdBytes, err := hex.DecodeString(receiver.AssetId)
					if err != nil {
						return nil, fmt.Errorf("failed to decode asset id: %s", err)
					}

					var assetId [32]byte
					copy(assetId[:], assetIdBytes)

					assetDetails, err := getAssetFromIntents(intents, assetId)
					if err != nil {
						return nil, fmt.Errorf("failed to get asset from intents: %s", err)
					}

					assetDetails.Outputs = []asset.AssetOutput{{
						PublicKey: *teleportKey,
						Vout:      0,
						Amount:    receiver.AssetAmount,
					}}

					assetDetails.Inputs = []asset.AssetInput{}

					emptyBatchId := make([]byte, 32)
					assetOpretrun, err := assetDetails.EncodeOpret(emptyBatchId)
					if err != nil {
						return nil, fmt.Errorf("failed to encode asset opreturn: %s", err)
					}

					vtxoScript, err := script.P2TRScript(pubkey)
					if err != nil {
						return nil, fmt.Errorf("failed to create script: %s", err)
					}

					log.Printf("this is the teleport script %+v", vtxoScript)
					leaves = append(leaves, tree.Leaf{
						Script:              hex.EncodeToString(vtxoScript),
						Amount:              receiver.Amount,
						CosignersPublicKeys: cosignersPublicKeys[i],
						AssetScript:         string(assetOpretrun.PkScript),
					})

					continue
				}

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

				log.Printf("this is the vtxo script %s", hex.EncodeToString(vtxoScript))

				leaves = append(leaves, tree.Leaf{
					Script:              hex.EncodeToString(vtxoScript),
					Amount:              receiver.Amount,
					CosignersPublicKeys: cosignersPublicKeys[i],
				})
			}
		}
	}
	return leaves, nil
}

func taprootOutputScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).Script()
}

func getAssetFromIntents(
	intents []domain.Intent, assetId [32]byte,
) (*asset.Asset, error) {

	for _, intent := range intents {
		log.Printf("intents decoded %+v", intent)
		for _, input := range intent.Inputs {
			if input.Asset != nil {
				decodedAsset, _, err := asset.DecodeAssetFromOpret(input.Asset)
				if err != nil {
					return nil, fmt.Errorf("failed to decode asset from input: %s", err)
				}

				log.Printf("asset %+v", decodedAsset)

				if decodedAsset.AssetId == assetId {
					return decodedAsset, nil
				}
			}

		}
	}
	return nil, fmt.Errorf("asset with id %x not found in intents", assetId)
}
