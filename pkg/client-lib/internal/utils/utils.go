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
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"golang.org/x/crypto/pbkdf2"
)

func CoinSelect(
	boardingUtxos []types.Utxo, vtxos []types.VtxoWithTapTree,
	amount, dust uint64, withoutExpirySorting bool,
) ([]types.Utxo, []types.VtxoWithTapTree, uint64, error) {
	selected, notSelected := make([]types.VtxoWithTapTree, 0), make([]types.VtxoWithTapTree, 0)
	selectedBoarding, notSelectedBoarding := make([]types.Utxo, 0), make([]types.Utxo, 0)
	selectedAmount := uint64(0)

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
			break
		}

		selectedBoarding = append(selectedBoarding, boardingUtxo)
		selectedAmount += boardingUtxo.Amount
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.Amount
	}

	if selectedAmount < amount {
		return nil, nil, 0, fmt.Errorf("not enough funds to cover amount %d", amount)
	}

	change := selectedAmount - amount

	if change < dust {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].Amount
		} else if len(notSelectedBoarding) > 0 {
			selectedBoarding = append(selectedBoarding, notSelectedBoarding[0])
			change += notSelectedBoarding[0].Amount
		}
	}

	return selectedBoarding, selected, change, nil
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

func FilterVtxosByExpiry(vtxos []types.Vtxo, expiryThreshold int64) []types.Vtxo {
	now := time.Now()
	threshold := time.Duration(expiryThreshold) * time.Second

	nearExpiry := make([]types.Vtxo, 0, len(vtxos))
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
