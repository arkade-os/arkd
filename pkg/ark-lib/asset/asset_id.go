package asset

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// TX_HASH_SIZE is the size of a transaction hash in bytes.
const (
	TX_HASH_SIZE = chainhash.HashSize
	// ASSET_ID_SIZE is the serialized size of an AssetId in bytes (32-byte txid + 2-byte index).
	ASSET_ID_SIZE = 34
	// AssetVersion is the current version byte used for asset serialization.
	AssetVersion byte = 0x01
)

// emptyTxHash is a zero-filled transaction hash used to detect invalid asset IDs.
var emptyTxHash = chainhash.Hash(make([]byte, chainhash.HashSize))

// AssetId uniquely identifies an asset by the transaction hash of its issuance and the group index
// in the asset packet of the transaction.
type AssetId struct {
	// Txid is the hash of the issuance transaction.
	Txid chainhash.Hash
	// Index is the position of the asset group within the asset packet of the issuance transaction.
	Index uint16
}

// NewAssetId creates an AssetId from a hex-encoded transaction ID string and a
// group index. Returns an error if the txid is empty, malformed, or all zeros.
func NewAssetId(txid string, index uint16) (*AssetId, error) {
	if len(txid) <= 0 {
		return nil, fmt.Errorf("missing txid")
	}
	if len(txid) != chainhash.HashSize*2 {
		return nil, fmt.Errorf(
			"invalid txid length, got %d want %d", len(txid), chainhash.HashSize*2,
		)
	}

	txHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		if strings.Contains(err.Error(), "encoding/hex") {
			return nil, fmt.Errorf("invalid txid format")
		}
		if errors.Is(err, chainhash.ErrHashStrSize) {
			return nil, fmt.Errorf("invalid txid length, got %d want 64", len(txid))
		}
		return nil, err
	}
	assetId := AssetId{Txid: *txHash, Index: index}
	if err := assetId.validate(); err != nil {
		return nil, err
	}
	return &assetId, nil
}

// NewAssetIdFromString parses a hex-encoded string into an AssetId.
func NewAssetIdFromString(s string) (*AssetId, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset id format, must be hex")
	}

	return NewAssetIdFromBytes(buf)
}

// NewAssetIdFromBytes deserializes an AssetId from a raw byte slice.
func NewAssetIdFromBytes(buf []byte) (*AssetId, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing asset id")
	}
	r := bytes.NewReader(buf)
	return newAssetIdFromReader(r)
}

// Serialize encodes the AssetId into a byte slice.
func (a AssetId) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := a.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized AssetId.
func (a AssetId) String() string {
	// nolint
	buf, _ := a.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks that the AssetId does not contain an all-zero txid.
func (a AssetId) validate() error {
	if a.Txid.IsEqual(&emptyTxHash) {
		return fmt.Errorf("empty txid")
	}
	return nil
}

// serialize writes the AssetId fields (txid then index) to the given writer.
func (a AssetId) serialize(w io.Writer) error {
	if err := serializeTxHash(w, a.Txid); err != nil {
		return err
	}
	return serializeUint16(w, a.Index)
}

// newAssetIdFromReader deserializes an AssetId by reading the txid and index
// from the given reader. Returns an error if the data is too short or invalid.
func newAssetIdFromReader(r *bytes.Reader) (*AssetId, error) {
	if r.Len() < ASSET_ID_SIZE {
		return nil, fmt.Errorf("invalid asset id length: got %d, want %d", r.Len(), ASSET_ID_SIZE)
	}

	txid, err := deserializeTxHash(r)
	if err != nil {
		return nil, err
	}
	index, err := deserializeUint16(r)
	if err != nil {
		return nil, err
	}

	assetId := AssetId{Txid: txid, Index: index}

	// Ensure the txid is not empty (all zeros)
	if err := assetId.validate(); err != nil {
		return nil, err
	}

	return &assetId, nil
}
