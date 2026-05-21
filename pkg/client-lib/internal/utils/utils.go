package utils

import (
	"fmt"
	"sort"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// CoinSelect selects among boarding utxos and vtxos to cover the total amount of the outputs
// it includes fee computation of the input and output thanks to feeEstimator
// the change is expressed in btc sats
func CoinSelect(
	boardingUtxos []clientlib.Utxo, vtxos []clientlib.Vtxo,
	outputs []clientlib.Receiver, dust uint64, feeEstimator *arkfee.Estimator,
) ([]clientlib.Utxo, []clientlib.Vtxo, uint64, error) {
	selected, notSelected := make([]clientlib.Vtxo, 0), make([]clientlib.Vtxo, 0)
	selectedBoarding, notSelectedBoarding := make([]clientlib.Utxo, 0), make([]clientlib.Utxo, 0)
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
		return !vtxos[i].ExpiresAt.Before(vtxos[j].ExpiresAt)
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

// CoinSelectAsset selects a set of vtxos holding a specific asset amount
// the change is expressed in asset sats
func CoinSelectAsset(
	vtxos []clientlib.Vtxo, amount uint64,
	assetID string, withoutExpirySorting bool,
) ([]clientlib.Vtxo, uint64, error) {
	selected := make([]clientlib.Vtxo, 0)
	selectedAmount := uint64(0)

	filteredVtxos := make([]clientlib.Vtxo, 0)

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
			return !vtxos[i].ExpiresAt.Before(vtxos[j].ExpiresAt)
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

func IsOnchainOnly(receivers []clientlib.Receiver) bool {
	for _, receiver := range receivers {
		if !receiver.IsOnchain() {
			return false
		}
	}

	return true
}
