package utils

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"golang.org/x/crypto/pbkdf2"
)

// CoinSelect selects among boarding utxos and vtxos to cover the total amount of the outputs
// it includes fee computation of the input and output thanks to feeEstimator
// the change is expressed in btc sats
// dust and minChangeAmount are both floors on the change, and differ in what
// happens when the selection can't reach them: a change short of dust alone is
// given up (it couldn't be turned into a spendable vtxo anyway), while a change
// short of minChangeAmount is an error, because the caller asked to keep it.
// Pass minChangeAmount 0 to accept any change the dust limit allows; callers
// building a tx that must conserve value exactly have to pass one, since giving
// the change up would unbalance the tx. A selection producing no change at all
// is always accepted, whatever the floors are.
func CoinSelect(
	boardingUtxos []types.Utxo, vtxos []types.VtxoWithTapTree,
	outputs []types.Receiver, dust uint64, withoutExpirySorting bool,
	feeEstimator *arkfee.Estimator, minChangeAmount uint64,
) ([]types.Utxo, []types.VtxoWithTapTree, uint64, error) {
	selected, notSelected := make([]types.VtxoWithTapTree, 0), make([]types.VtxoWithTapTree, 0)
	selectedBoarding, notSelectedBoarding := make([]types.Utxo, 0), make([]types.Utxo, 0)
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

	if !withoutExpirySorting {
		// sort vtxos by expiration (oldest last)
		sort.SliceStable(vtxos, func(i, j int) bool {
			return !vtxos[i].ExpiresAt.Before(vtxos[j].ExpiresAt)
		})

		sort.SliceStable(boardingUtxos, func(i, j int) bool {
			return boardingUtxos[i].SpendableAt.Before(boardingUtxos[j].SpendableAt)
		})
	}

	for _, boardingUtxo := range boardingUtxos {
		if selectedAmount >= amount {
			notSelectedBoarding = append(notSelectedBoarding, boardingUtxo)
			continue
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
			continue
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

	// selectMoreCoins moves the next unselected coin into the selection,
	// preferring vtxos over boarding utxos, and adds its amount, net of the fee
	// to spend it, to the change. It returns false if no coin is left.
	selectMoreCoins := func() (bool, error) {
		if len(notSelected) > 0 {
			vtxo := notSelected[0]
			notSelected = notSelected[1:]
			selected = append(selected, vtxo)
			change += vtxo.Amount

			if feeEstimator != nil {
				fees, err := feeEstimator.EvalOffchainInput(vtxo.ToArkFeeInput())
				if err != nil {
					return false, err
				}
				change -= uint64(fees.ToSatoshis())
			}
			return true, nil
		}

		if len(notSelectedBoarding) > 0 {
			utxo := notSelectedBoarding[0]
			notSelectedBoarding = notSelectedBoarding[1:]
			selectedBoarding = append(selectedBoarding, utxo)
			change += utxo.Amount

			if feeEstimator != nil {
				fees, err := feeEstimator.EvalOnchainInput(utxo.ToArkFeeInput())
				if err != nil {
					return false, err
				}
				change -= uint64(fees.ToSatoshis())
			}
			return true, nil
		}

		return false, nil
	}

	// A change below the dust limit can't be turned into a spendable vtxo, and
	// the caller may require an even higher minimum: keep pulling in coins
	// until the change clears both floors, or until nothing is left to pull.
	floor := max(dust, minChangeAmount)
	for change > 0 && change < floor {
		selectedMore, err := selectMoreCoins()
		if err != nil {
			return nil, nil, 0, err
		}
		if !selectedMore {
			break
		}
	}

	// a selection producing no change is always valid, otherwise a change the
	// caller explicitly asked to keep above a minimum can't be given up.
	if change > 0 && change < floor {
		if change < minChangeAmount {
			return nil, nil, 0, fmt.Errorf(
				"selected coins leave a change of %d, below the min change amount %d",
				change, minChangeAmount,
			)
		}
		change = 0
	}

	return selectedBoarding, selected, change, nil
}

// CoinSelectAsset selects a set of vtxos holding a specific asset amount
// the change is expressed in asset sats
func CoinSelectAsset(
	vtxos []types.VtxoWithTapTree, amount uint64,
	assetID string, withoutExpirySorting bool,
) ([]types.VtxoWithTapTree, uint64, error) {
	selected := make([]types.VtxoWithTapTree, 0)
	selectedAmount := uint64(0)

	filteredVtxos := make([]types.VtxoWithTapTree, 0)

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
		// sort vtxos by expiration (older first)
		sort.SliceStable(vtxos, func(i, j int) bool {
			return vtxos[i].ExpiresAt.Before(vtxos[j].ExpiresAt)
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

func IsOnchainOnly(receivers []types.Receiver) bool {
	for _, receiver := range receivers {
		if !receiver.IsOnchain() {
			return false
		}
	}

	return true
}

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

func GenerateRandomPrivateKey() (*btcec.PrivateKey, error) {
	prvkey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return prvkey, nil
}

func HashPassword(password []byte) []byte {
	hash := sha256.Sum256(password)
	return hash[:]
}

func EncryptAES256(privateKey, password []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("missing plaintext private key")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing encryption password")
	}

	key, salt, err := deriveKey(password, nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, privateKey, nil)
	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func DecryptAES256(encrypted, password []byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, fmt.Errorf("missing encrypted mnemonic")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing decryption password")
	}

	salt := encrypted[len(encrypted)-32:]
	data := encrypted[:len(encrypted)-32]

	key, _, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, text := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	// #nosec G407
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	return plaintext, nil
}

var lock = &sync.Mutex{}

// deriveKey derives a 32 byte array key from a custom passhprase
func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	lock.Lock()
	defer lock.Unlock()

	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	iterations := 10000
	keySize := 32
	key := pbkdf2.Key(password, salt, iterations, keySize, sha256.New)
	return key, salt, nil
}

type ChunkJSONStream struct {
	Msg []byte
	Err error
}

func ListenToJSONStream(url string, chunkCh chan ChunkJSONStream) {
	defer close(chunkCh)

	httpClient := &http.Client{Timeout: time.Second * 0}

	var resp *http.Response

	for resp == nil {
		var err error
		resp, err = httpClient.Get(url)
		if err != nil {
			chunkCh <- ChunkJSONStream{Err: err}
			return
		}

		// nolint:errcheck
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			// handle 524 error by retrying
			if resp.StatusCode == 524 {
				//nolint:errcheck
				resp.Body.Close()

				resp = nil
				continue
			}

			chunkCh <- ChunkJSONStream{Err: fmt.Errorf("got unexpected status %d code", resp.StatusCode)}
			return
		}
	}

	reader := bufio.NewReader(resp.Body)
	for {
		msg, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				err = client.ErrConnectionClosedByServer
			}
			chunkCh <- ChunkJSONStream{Err: err}
			return
		}
		msg = bytes.Trim(msg, "\n")
		chunkCh <- ChunkJSONStream{Msg: msg}
	}
}

func FilterVtxosByExpiry(
	vtxos []types.VtxoWithTapTree, expiryThreshold int64,
) []types.VtxoWithTapTree {
	now := time.Now()
	threshold := time.Duration(expiryThreshold) * time.Second

	nearExpiry := make([]types.VtxoWithTapTree, 0, len(vtxos))
	for _, vtxo := range vtxos {
		// time until expiry
		timeLeft := vtxo.ExpiresAt.Sub(now)

		// if already expired or within threshold
		if timeLeft <= threshold {
			nearExpiry = append(nearExpiry, vtxo)
		}
	}

	return nearExpiry
}

func SortVtxosByExpiry(vtxos []types.Vtxo) []types.Vtxo {
	sort.SliceStable(vtxos, func(i, j int) bool {
		return vtxos[i].ExpiresAt.Before(vtxos[j].ExpiresAt)
	})
	return vtxos
}
