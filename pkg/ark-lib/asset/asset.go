package asset

import (
	"encoding/hex"
	"fmt"
)

const TX_HASH_SIZE = 32
const ASSET_ID_SIZE = 34

const AssetVersion byte = 0x01

type AssetId struct {
	Txid  [TX_HASH_SIZE]byte
	Index uint16
}

func (a AssetId) ToString() string {
	var buf [ASSET_ID_SIZE]byte
	copy(buf[:TX_HASH_SIZE], a.Txid[:])
	// Big endian encoding for index
	buf[ASSET_ID_SIZE-2] = byte(a.Index >> 8)
	buf[ASSET_ID_SIZE-1] = byte(a.Index)
	return hex.EncodeToString(buf[:])
}

// String implements fmt.Stringer
func (a AssetId) String() string {
	return a.ToString()
}

func AssetIdFromString(s string) (*AssetId, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(buf) != ASSET_ID_SIZE {
		return nil, fmt.Errorf("invalid asset id length: %d", len(buf))
	}

	var assetId AssetId
	copy(assetId.Txid[:], buf[:TX_HASH_SIZE])
	// Big endian decoding for index
	assetId.Index = uint16(buf[ASSET_ID_SIZE-2])<<8 | uint16(buf[ASSET_ID_SIZE-1])
	return &assetId, nil
}
