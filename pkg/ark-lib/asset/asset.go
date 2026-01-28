package asset

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const TX_HASH_SIZE = chainhash.HashSize
const ASSET_ID_SIZE = 34

const AssetVersion byte = 0x01

type AssetId struct {
	Txid  [TX_HASH_SIZE]byte
	Index uint16
}

func (a AssetId) String() string {
	return hex.EncodeToString(a.Serialize())
}

func NewAssetIdFromString(s string) (*AssetId, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return NewAssetIdFromBytes(buf)
}

func NewAssetIdFromBytes(b []byte) (*AssetId, error) {
	if len(b) != ASSET_ID_SIZE {
		return nil, fmt.Errorf("invalid asset id length: %d", len(b))
	}

	var assetId AssetId
	copy(assetId.Txid[:], b[:TX_HASH_SIZE])
	// Big endian decoding for index
	assetId.Index = uint16(b[ASSET_ID_SIZE-2])<<8 | uint16(b[ASSET_ID_SIZE-1])
	return &assetId, nil
}

func (a AssetId) Serialize() []byte {
	var buf [ASSET_ID_SIZE]byte
	copy(buf[:TX_HASH_SIZE], a.Txid[:])
	// Big endian encoding for index
	buf[ASSET_ID_SIZE-2] = byte(a.Index >> 8)
	buf[ASSET_ID_SIZE-1] = byte(a.Index)
	return buf[:]
}
