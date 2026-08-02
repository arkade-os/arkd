package clientlib

import (
	"encoding/hex"
	"fmt"
	"sort"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// NetworkFromString resolves the textual network name reported by the server (mainnet, testnet,
// testnet4, signet, mutinynet, regtest) into the matching arklib.Network value.
// Unknown values fall back to arklib.Bitcoin (mainnet).
func NetworkFromString(net string) arklib.Network {
	switch net {
	case arklib.BitcoinTestNet.Name:
		return arklib.BitcoinTestNet
	case arklib.BitcoinTestNet4.Name:
		return arklib.BitcoinTestNet4
	case arklib.BitcoinSigNet.Name:
		return arklib.BitcoinSigNet
	case arklib.BitcoinMutinyNet.Name:
		return arklib.BitcoinMutinyNet
	case arklib.BitcoinRegTest.Name:
		return arklib.BitcoinRegTest
	case arklib.Bitcoin.Name:
		fallthrough
	default:
		return arklib.Bitcoin
	}
}

// ToBitcoinNetwork maps an arklib.Network to the corresponding btcd chaincfg.Params used to
// decode/encode Bitcoin addresses on that network. Unknown networks fall back to mainnet params.
func ToBitcoinNetwork(net arklib.Network) chaincfg.Params {
	switch net.Name {
	case arklib.Bitcoin.Name:
		return chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		return chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	default:
		return chaincfg.MainNetParams
	}
}

// CoinSelect picks boarding utxos and vtxos to cover the BTC amount of the given outputs.
// When feeEstimator is non-nil it also accounts for the per-input and per-output fees, growing
// the target amount accordingly.
// If the computed change is below dust it is folded into the selection by adding one more input
// (preferring an offchain vtxo, then a boarding utxo) when one is available, otherwise the change
// is dropped to zero. Returns the selected boarding utxos, the selected vtxos, and the leftover
// change in sats.
func CoinSelect(
	boardingUtxos []Utxo, vtxos []Vtxo,
	outputs []Receiver, dust uint64, feeEstimator *arkfee.Estimator,
) ([]Utxo, []Vtxo, uint64, error) {
	selected, notSelected := make([]Vtxo, 0), make([]Vtxo, 0)
	selectedBoarding, notSelectedBoarding := make([]Utxo, 0), make([]Utxo, 0)
	selectedAmount := uint64(0)

	amount := uint64(0)
	for _, output := range outputs {
		amount += output.Amount
		if feeEstimator != nil {
			var fees arkfee.FeeAmount
			var err error
			arkFeeOutput := output.ToArkFeeOutput()
			if output.IsOnchain() {
				fees, err = feeEstimator.EvalOnchainOutput(arkFeeOutput)
			} else {
				fees, err = feeEstimator.EvalOffchainOutput(arkFeeOutput)
			}
			if err != nil {
				return nil, nil, 0, err
			}
			amount += uint64(fees.ToSatoshis())
		}
	}

	// Sort vtxos by expiration (oldest last)
	sort.SliceStable(vtxos, func(i, j int) bool {
		return vtxos[i].ExpiresAt.After(vtxos[j].ExpiresAt)
	})

	sort.SliceStable(boardingUtxos, func(i, j int) bool {
		return boardingUtxos[i].RedeemableAt.Before(boardingUtxos[j].RedeemableAt)
	})

	for _, boardingUtxo := range boardingUtxos {
		if selectedAmount >= amount {
			notSelectedBoarding = append(notSelectedBoarding, boardingUtxo)
			break
		}

		selectedBoarding = append(selectedBoarding, boardingUtxo)
		selectedAmount += boardingUtxo.Amount

		if feeEstimator != nil {
			fees, err := feeEstimator.EvalOnchainInput(boardingUtxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, 0, err
			}
			amount += uint64(fees.ToSatoshis())
		}
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.Amount

		if feeEstimator != nil {
			feesForInput, err := feeEstimator.EvalOffchainInput(vtxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, 0, err
			}
			amount += uint64(feesForInput.ToSatoshis())
		}
	}

	if selectedAmount < amount {
		return nil, nil, 0, fmt.Errorf("not enough funds to cover amount %d", amount)
	}

	change := selectedAmount - amount

	if feeEstimator != nil {
		fees, err := feeEstimator.EvalOffchainOutput(arkfee.Output{
			Amount: change,
		})
		if err != nil {
			return nil, nil, 0, err
		}
		change -= uint64(fees.ToSatoshis())
	}

	if change < dust {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].Amount

			if feeEstimator != nil {
				fees, err := feeEstimator.EvalOffchainInput(notSelected[0].ToArkFeeInput())
				if err != nil {
					return nil, nil, 0, err
				}
				change -= uint64(fees.ToSatoshis())
			}
		} else if len(notSelectedBoarding) > 0 {
			selectedBoarding = append(selectedBoarding, notSelectedBoarding[0])
			change += notSelectedBoarding[0].Amount

			if feeEstimator != nil {
				fees, err := feeEstimator.EvalOnchainInput(notSelectedBoarding[0].ToArkFeeInput())
				if err != nil {
					return nil, nil, 0, err
				}
				change -= uint64(fees.ToSatoshis())
			}
		} else {
			change = 0
		}
	}

	return selectedBoarding, selected, change, nil
}

// CoinSelectAsset picks vtxos that, combined, hold at least `amount` units of the asset identified
// by assetID. Vtxos with no matching asset are filtered out up front. By default vtxos are sorted
// so that the ones nearest to expiry sit at the end of the slice, and the loop picks from the
// front — i.e. it preserves the soonest-to-expire balance for as long as possible.
// Pass withoutExpirySorting=true to consume the input order verbatim (useful when the caller has
// already ordered the vtxos). Returns the selected vtxos plus the leftover change in asset units.
func CoinSelectAsset(
	vtxos []Vtxo, amount uint64,
	assetID string, withoutExpirySorting bool,
) ([]Vtxo, uint64, error) {
	selected := make([]Vtxo, 0)
	selectedAmount := uint64(0)

	filteredVtxos := make([]Vtxo, 0)

	// filter out vtxos holding other assets (or no assets)
	for _, vtxo := range vtxos {
		if len(vtxo.Assets) > 0 {
			for _, asset := range vtxo.Assets {
				if asset.AssetId == assetID {
					filteredVtxos = append(filteredVtxos, vtxo)
					break
				}
			}
		}
	}

	vtxos = filteredVtxos

	if !withoutExpirySorting {
		// Sort vtxos by expiration (oldest last)
		sort.SliceStable(vtxos, func(i, j int) bool {
			return vtxos[i].ExpiresAt.After(vtxos[j].ExpiresAt)
		})
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			break
		}
		selected = append(selected, vtxo)
		for _, asset := range vtxo.Assets {
			if asset.AssetId == assetID {
				selectedAmount += asset.Amount
				break
			}
		}
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds to cover amount %d", amount)
	}

	change := selectedAmount - amount
	return selected, change, nil
}

// ParseBitcoinAddress attempts to decode addr as a Bitcoin address on the given network.
// Returns (true, output script, nil) on success, (false, nil, nil) when the address can't be
// decoded on that network (i.e. the caller can treat the input as "not an on-chain address"), and
// (false, nil, err) only when a successfully-decoded address fails to produce a PayToAddr script.
func ParseBitcoinAddress(addr string, net chaincfg.Params) (
	bool, []byte, error,
) {
	btcAddr, err := btcutil.DecodeAddress(addr, &net)
	if err != nil {
		return false, nil, nil
	}

	onchainScript, err := txscript.PayToAddrScript(btcAddr)
	if err != nil {
		return false, nil, err
	}
	return true, onchainScript, nil
}

// ParseClosure derives the on-chain pkScript and the taproot merkle proof that authorizes the
// given closure (typically the forfeit script) under the vtxo's tapscript tree.
// Used by Vtxo/Utxo to expose the signing leaf needed when adding the input to an intent proof or
// ark transaction. Returns errors scoped to outpoint so failures are traceable to a specific input.
func ParseClosure(
	outpoint Outpoint, closure script.Closure, tapscripts []string,
) ([]byte, *arklib.TaprootMerkleProof, error) {
	if closure == nil {
		return nil, nil, fmt.Errorf("%s has no signing closure", outpoint.String())
	}
	if len(tapscripts) <= 0 {
		return nil, nil, fmt.Errorf("%s has no tapscripts", outpoint.String())
	}

	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid tapscripts: %w", outpoint.String(), err)
	}
	forfeitScript, err := closure.Script()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%s has invalid signing closure: %w", outpoint.String(), err,
		)
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid taptree: %w", outpoint.String(), err)
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%s has invalid signing script: %w", outpoint.String(), err,
		)
	}
	pkScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid tapkey: %w", outpoint.String(), err)
	}

	return pkScript, leafProof, nil
}

// EcPubkeyFromHex decodes a hex-encoded secp256k1 public key and parses it into a
// *btcec.PublicKey.
// The input may be compressed or uncompressed, as accepted by btcec.ParsePubKey.
// It returns an error if the string is not valid hex or does not encode a valid public key.
func EcPubkeyFromHex(pubkey string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(buf)
}
