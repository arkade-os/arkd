package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/pbkdf2"
)

func CoinSelect(
	boardingUtxos []types.Utxo,
	vtxos []client.TapscriptsVtxo,
	amount,
	dust uint64,
	sortByExpirationTime bool,
) ([]types.Utxo, []client.TapscriptsVtxo, uint64, error) {
	selected, notSelected := make([]client.TapscriptsVtxo, 0), make([]client.TapscriptsVtxo, 0)
	selectedBoarding, notSelectedBoarding := make([]types.Utxo, 0), make([]types.Utxo, 0)
	selectedAmount := uint64(0)

	if sortByExpirationTime {
		// sort vtxos by expiration (older first)
		sort.SliceStable(vtxos, func(i, j int) bool {
			return vtxos[i].ExpiresAt.Before(vtxos[j].ExpiresAt)
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

func IsOnchainOnly(receivers []client.Output) bool {
	for _, receiver := range receivers {
		isOnChain := len(receiver.Address) > 0

		if !isOnChain {
			return false
		}
	}

	return true
}

func NetworkFromString(net string) common.Network {
	switch net {
	case common.BitcoinTestNet.Name:
		return common.BitcoinTestNet
	case common.BitcoinTestNet4.Name:
		return common.BitcoinTestNet4
	case common.BitcoinSigNet.Name:
		return common.BitcoinSigNet
	case common.BitcoinMutinyNet.Name:
		return common.BitcoinMutinyNet
	case common.BitcoinRegTest.Name:
		return common.BitcoinRegTest
	case common.Bitcoin.Name:
		fallthrough
	default:
		return common.Bitcoin
	}
}

func ToBitcoinNetwork(net common.Network) chaincfg.Params {
	switch net.Name {
	case common.Bitcoin.Name:
		return chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	//case common.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return chaincfg.TestNet4Params
	case common.BitcoinSigNet.Name:
		return chaincfg.SigNetParams
	case common.BitcoinMutinyNet.Name:
		return common.MutinyNetSigNetParams
	case common.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	default:
		return chaincfg.MainNetParams
	}
}

func GenerateRandomPrivateKey() (*secp256k1.PrivateKey, error) {
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

func DeriveWsURl(baseUrl string, wsUrl string) string {
	if wsUrl == "" {
		parsedUrl, err := url.Parse(baseUrl)
		if err != nil || parsedUrl.Scheme == "" {
			// fallback if baseUrl is malformed or empty
			wsUrl = "ws://" + baseUrl
		} else {
			switch parsedUrl.Scheme {
			case "http":
				parsedUrl.Scheme = "ws"
			case "https":
				parsedUrl.Scheme = "wss"
			case "ws", "wss":
				// already correct scheme
			default:
				// default fallback
				parsedUrl.Scheme = "ws"
			}
			wsUrl = parsedUrl.String()
		}
		// Append "/ws" if not already present
		if !strings.HasSuffix(wsUrl, "/ws") {
			wsUrl = strings.TrimRight(wsUrl, "/") + "/ws"
		}
	}

	return wsUrl
}
