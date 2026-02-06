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

const TX_HASH_SIZE = chainhash.HashSize
const ASSET_ID_SIZE = 34

const AssetVersion byte = 0x01

var emptyTxHash = chainhash.Hash(make([]byte, chainhash.HashSize))

type AssetId struct {
	Txid  chainhash.Hash
	Index uint16
}

func NewAssetId(txid string, index uint16) (*AssetId, error) {
	if len(txid) <= 0 {
		return nil, fmt.Errorf("missing txid")
	}
	if len(txid) != chainhash.HashSize * 2 {
		return nil, fmt.Errorf("invalid txid length, got %d want %d", len(txid), chainhash.HashSize * 2)
	}
	
	txHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		if strings.Contains(err.Error(), "encoding/hex") {
			return nil, fmt.Errorf("invalid txid format")
		}
		if errors.Is(err, chainhash.ErrHashStrSize) {
			return nil, fmt.Errorf(
				"invalid txid length, got %d want 64", len(txid))
		}
		return nil, err
	}
	assetId := AssetId{Txid: *txHash, Index: index}
	if err := assetId.validate(); err != nil {
		return nil, err
	}
	return &assetId, nil
}

func NewAssetIdFromString(s string) (*AssetId, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset id format, must be hex")
	}

	return NewAssetIdFromBytes(buf)
}

func NewAssetIdFromBytes(buf []byte) (*AssetId, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing asset id")
	}
	r := bytes.NewReader(buf)
	return newAssetIdFromReader(r)
}

func (a AssetId) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := a.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (a AssetId) String() string {
	// nolint
	buf, _ := a.Serialize()
	return hex.EncodeToString(buf)
}

func (a AssetId) validate() error {
	if a.Txid.IsEqual(&emptyTxHash) {
		return fmt.Errorf("empty txid")
	}
	return nil
}

func (a AssetId) serialize(w io.Writer) error {
	if err := serializeTxHash(w, a.Txid); err != nil {
		return err
	}
	return serializeUint16(w, a.Index)
}

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

	// make sure the txid is not a slice of 0x0000.. 32-bytes
	if err := assetId.validate(); err != nil {
		return nil, err
	}

	return &assetId, nil
}
