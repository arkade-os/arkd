package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-wallet/identity"
	identitystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store"
	identityfilestore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/file"
	identityinmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lntypes"
)

func getClient(
	supportedClients supportedType[clientFactory],
	clientType, serverUrl string, withMonitorConn bool,
) (clientlib.Client, error) {
	factory := supportedClients[clientType]
	return factory(serverUrl, withMonitorConn)
}

func getIndexer(
	supportedIndexers supportedType[indexerFactory],
	clientType, serverUrl string, withMonitorConn bool,
) (clientlib.Indexer, error) {
	factory := supportedIndexers[clientType]
	return factory(serverUrl, withMonitorConn)
}

func getSingleKeyIdentity(datadir, storeType string) (clientlib.Identity, error) {
	store, err := getIdentityStore(storeType, datadir)
	if err != nil {
		return nil, err
	}

	return identity.NewIdentity(store)
}

func getIdentityStore(storeType, datadir string) (identitystore.IdentityStore, error) {
	switch storeType {
	case InMemoryStore:
		return identityinmemorystore.NewStore()
	case FileStore:
		return identityfilestore.NewStore(datadir)
	default:
		return nil, fmt.Errorf("unknown identity store type")
	}
}

func filterByOutpoints(vtxos []clientlib.Vtxo, outpoints []clientlib.Outpoint) []clientlib.Vtxo {
	filtered := make([]clientlib.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		for _, outpoint := range outpoints {
			if vtxo.Outpoint == outpoint {
				filtered = append(filtered, vtxo)
			}
		}
	}
	return filtered
}

func inputsToDerivationPath(inputs []clientlib.Outpoint, notesInputs []string) string {
	// sort arknotes
	slices.SortStableFunc(notesInputs, func(i, j string) int {
		return strings.Compare(i, j)
	})

	// sort outpoints
	slices.SortStableFunc(inputs, func(i, j clientlib.Outpoint) int {
		txidCmp := strings.Compare(i.Txid, j.Txid)
		if txidCmp != 0 {
			return txidCmp
		}
		return int(i.VOut - j.VOut)
	})

	// serialize outpoints and arknotes

	var buf bytes.Buffer

	for _, input := range inputs {
		buf.WriteString(input.Txid)
		buf.WriteString(strconv.Itoa(int(input.VOut)))
	}

	for _, note := range notesInputs {
		buf.WriteString(note)
	}

	// hash the serialized data
	hash := sha256.Sum256(buf.Bytes())

	// convert hash to bip32 derivation path
	// split the 32-byte hash into 8 uint32 values (4 bytes each)
	path := "m"
	for i := 0; i < 8; i++ {
		// Convert 4 bytes to uint32 using big-endian encoding
		segment := binary.BigEndian.Uint32(hash[i*4 : (i+1)*4])
		path += fmt.Sprintf("/%d'", segment)
	}

	return path
}

func extractCollaborativePath(tapscripts []string) ([]byte, *arklib.TaprootMerkleProof, error) {
	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, err
	}

	forfeitClosures := vtxoScript.ForfeitClosures()
	if len(forfeitClosures) <= 0 {
		return nil, nil, fmt.Errorf("no exit closures found")
	}

	forfeitClosure := forfeitClosures[0]
	forfeitScript, err := forfeitClosure.Script()
	if err != nil {
		return nil, nil, err
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get taproot merkle proof: %s", err)
	}
	pkScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return pkScript, leafProof, nil
}

func getOffchainBalanceDetails(
	amountByExpiration map[int64]uint64,
) (int64, []types.VtxoDetails) {
	nextExpiration := int64(0)
	details := make([]types.VtxoDetails, 0)
	for timestamp, amount := range amountByExpiration {
		if nextExpiration == 0 || timestamp < nextExpiration {
			nextExpiration = timestamp
		}

		fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
		details = append(
			details, types.VtxoDetails{
				ExpiryTime: fancyTime,
				Amount:     amount,
			},
		)
	}
	return nextExpiration, details
}

func getFancyTimeExpiration(nextExpiration int64) string {
	if nextExpiration == 0 {
		return ""
	}

	fancyTimeExpiration := ""
	t := time.Unix(nextExpiration, 0)
	if t.Before(time.Now().Add(48 * time.Hour)) {
		// print the duration instead of the absolute time
		until := time.Until(t)
		seconds := math.Abs(until.Seconds())
		minutes := math.Abs(until.Minutes())
		hours := math.Abs(until.Hours())

		if hours < 1 {
			if minutes < 1 {
				fancyTimeExpiration = fmt.Sprintf("%d seconds", int(seconds))
			} else {
				fancyTimeExpiration = fmt.Sprintf("%d minutes", int(minutes))
			}
		} else {
			fancyTimeExpiration = fmt.Sprintf("%d hours", int(hours))
		}
	} else {
		fancyTimeExpiration = t.Format(time.RFC3339)
	}
	return fancyTimeExpiration
}

func computeVSize(tx *wire.MsgTx) lntypes.VByte {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize() // including witness
	weight := totalSize + baseSize*3
	return lntypes.WeightUnit(uint64(weight)).ToVB()
}

func findVtxosSpentInSettlement(vtxos []clientlib.Vtxo, vtxo clientlib.Vtxo) []clientlib.Vtxo {
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSettled(vtxos, vtxo.CommitmentTxids[0])
}

func findVtxosSettled(vtxos []clientlib.Vtxo, id string) []clientlib.Vtxo {
	var result []clientlib.Vtxo
	leftVtxos := make([]clientlib.Vtxo, 0)
	for _, v := range vtxos {
		if v.SettledBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func findVtxosResultedFromSettledBy(vtxos []clientlib.Vtxo, commitmentTxid string) []clientlib.Vtxo {
	var result []clientlib.Vtxo
	for _, v := range vtxos {
		if v.Preconfirmed || len(v.CommitmentTxids) != 1 {
			continue
		}
		if v.CommitmentTxids[0] == commitmentTxid {
			result = append(result, v)
		}
	}
	return result
}

func findVtxosSpent(vtxos []clientlib.Vtxo, id string) []clientlib.Vtxo {
	var result []clientlib.Vtxo
	leftVtxos := make([]clientlib.Vtxo, 0)
	for _, v := range vtxos {
		if v.ArkTxid == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func reduceVtxosAmount(vtxos []clientlib.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []clientlib.Vtxo, vtxo clientlib.Vtxo) []clientlib.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSpentBy(vtxos []clientlib.Vtxo, spentByTxid string) []clientlib.Vtxo {
	var result []clientlib.Vtxo
	for _, v := range vtxos {
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []clientlib.Vtxo, spentByVtxos []clientlib.Vtxo) clientlib.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return clientlib.Vtxo{}
}

func ecPubkeyFromHex(pubkey string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(buf)
}

func toOutputScript(onchainAddress string, network arklib.Network) ([]byte, error) {
	netParams := clientlib.ToBitcoinNetwork(network)
	rcvAddr, err := btcutil.DecodeAddress(onchainAddress, &netParams)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(rcvAddr)
}

// validateOffchainAddress rejects everything that is not a valid offchain ark
// address. Used by methods whose receiver MUST be a vtxo destination
// (SendOffChain change, asset ops, RedeemNotes).
func validateOffchainAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	if _, err := arklib.DecodeAddressV0(addr); err != nil {
		return fmt.Errorf("invalid offchain receiver address: %w", err)
	}
	return nil
}

// validateOnchainAddress rejects everything that is not a valid onchain
// bitcoin address on the given network. Used by OnboardAgainAllExpiredBoardings.
func validateOnchainAddress(addr string, network arklib.Network) error {
	if addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	netParams := clientlib.ToBitcoinNetwork(network)
	if _, err := btcutil.DecodeAddress(addr, &netParams); err != nil {
		return fmt.Errorf("invalid onchain receiver address: %w", err)
	}
	return nil
}

// validateOffchainOrOnchainAddress accepts either an ark offchain address or
// a bitcoin onchain address on the given network. Used by Settle /
// CollaborativeExit, where batch-session outputs may legally be either.
func validateOffchainOrOnchainAddress(addr string, network arklib.Network) error {
	if addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	if _, offErr := arklib.DecodeAddressV0(addr); offErr == nil {
		return nil
	}
	netParams := clientlib.ToBitcoinNetwork(network)
	if _, onErr := btcutil.DecodeAddress(addr, &netParams); onErr == nil {
		return nil
	}
	return fmt.Errorf(
		"invalid receiver address: not a valid offchain or onchain bitcoin address",
	)
}

type supportedType[V any] map[string]V

func (t supportedType[V]) String() string {
	types := make([]string, 0, len(t))
	for tt := range t {
		types = append(types, tt)
	}
	return strings.Join(types, " | ")
}

func (t supportedType[V]) supports(typeStr string) bool {
	_, ok := t[typeStr]
	return ok
}

type clientFactory func(string, bool) (clientlib.Client, error)

type indexerFactory func(string, bool) (clientlib.Indexer, error)
