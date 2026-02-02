package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const TX_HASH_SIZE = chainhash.HashSize
const ASSET_ID_SIZE = 34

const AssetVersion byte = 0x01

type AssetId struct {
	Txid  chainhash.Hash
	Index uint16
}

func NewAssetId(txid string, index uint16) (*AssetId, error) {
	if len(txid) <= 0 {
		return nil, fmt.Errorf("missing txid")
	}
	buf, err := hex.DecodeString(txid)
	if err != nil {
		return nil, fmt.Errorf("invalid txid format, must be hex")
	}
	if len(buf) != chainhash.HashSize {
		return nil, fmt.Errorf(
			"invalid txid length, got %d want %d", len(txid), chainhash.HashSize,
		)
	}
	assetId := AssetId{Txid: chainhash.Hash(buf), Index: index}
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
	if bytes.Equal(a.Txid[:], make([]byte, chainhash.HashSize)) {
		return fmt.Errorf("empty txid")
	}
	return nil
}

func (a AssetId) serialize(w io.Writer) error {
	if err := serializeSlice(w, a.Txid[:]); err != nil {
		return err
	}
	return serializeUint16(w, a.Index)
}

func newAssetIdFromReader(r *bytes.Reader) (*AssetId, error) {
	if r.Len() < ASSET_ID_SIZE {
		return nil, fmt.Errorf("invalid asset id length: got %d, want %d", r.Len(), ASSET_ID_SIZE)
	}

	txid, err := deserializeSlice(r, chainhash.HashSize)
	if err != nil {
		return nil, err
	}
	index, err := deserializeUint16(r)
	if err != nil {
		return nil, err
	}

	assetId := AssetId{Txid: chainhash.Hash(txid), Index: index}

	// Make sure the txid is not a slice of 0x0000.. 32-bytes
	if err := assetId.validate(); err != nil {
		return nil, err
	}

	return &assetId, nil
}
