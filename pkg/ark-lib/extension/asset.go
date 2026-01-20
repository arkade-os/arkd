package extension

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

const TX_HASH_SIZE = 32
const ASSET_ID_SIZE = 34

const AssetVersion byte = 0x01

type AssetId struct {
	TxHash [TX_HASH_SIZE]byte
	Index  uint16
}

type AssetRefType uint8

const (
	AssetRefByID    AssetRefType = 0x01
	AssetRefByGroup AssetRefType = 0x02
)

type AssetRef struct {
	Type       AssetRefType
	AssetId    AssetId
	GroupIndex uint16
}

func AssetRefFromId(assetId AssetId) *AssetRef {
	return &AssetRef{
		Type:    AssetRefByID,
		AssetId: assetId,
	}
}

func AssetRefFromGroupIndex(groupIndex uint16) *AssetRef {
	return &AssetRef{
		Type:       AssetRefByGroup,
		GroupIndex: groupIndex,
	}
}

func (a AssetId) ToString() string {
	var buf [ASSET_ID_SIZE]byte
	copy(buf[:TX_HASH_SIZE], a.TxHash[:])
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
	copy(assetId.TxHash[:], buf[:TX_HASH_SIZE])
	// Big endian decoding for index
	assetId.Index = uint16(buf[ASSET_ID_SIZE-2])<<8 | uint16(buf[ASSET_ID_SIZE-1])
	return &assetId, nil
}

type AssetGroup struct {
	AssetId      *AssetId
	Immutable    bool
	Outputs      []AssetOutput
	ControlAsset *AssetRef
	Inputs       []AssetInput
	Metadata     []Metadata
}

type AssetPacket struct {
	Assets  []AssetGroup
	Version byte
}

type Metadata struct {
	Key   string
	Value string
}

type AssetOutput struct {
	Type   AssetType
	Vout   uint32 // For Local
	Amount uint64
}

type AssetType uint8

const (
	AssetTypeLocal  AssetType = 0x01
	AssetTypeIntent AssetType = 0x02
)

type AssetInput struct {
	Type   AssetType
	Vin    uint32
	Txid   [32]byte
	Amount uint64
}

func (g *AssetPacket) EncodeAssetPacket() (wire.TxOut, error) {
	opReturnPacket := &ExtensionPacket{
		Asset: g,
	}
	return opReturnPacket.EncodeExtensionPacket()
}

func DecodeAssetPacket(txOut wire.TxOut) (*AssetPacket, error) {
	packet, err := DecodeExtensionPacket(txOut)
	if err != nil {
		return nil, err
	}
	if packet.Asset == nil {
		return nil, errors.New("missing asset payload")
	}
	return packet.Asset, nil
}

func ContainsAssetPacket(opReturnData []byte) bool {
	payload, _, err := parsePacketOpReturn(opReturnData)
	return err == nil && len(payload) > 0
}

func ContainsSubKeyPacket(opReturnData []byte) bool {
	_, payload, err := parsePacketOpReturn(opReturnData)
	return err == nil && len(payload) > 0
}

func DeriveAssetPacketFromTx(arkTx wire.MsgTx) (*AssetPacket, int, error) {
	for i, output := range arkTx.TxOut {
		if ContainsAssetPacket(output.PkScript) {
			assetPacket, err := DecodeAssetPacket(*output)
			if err != nil {
				return nil, 0, fmt.Errorf("error decoding asset Opreturn: %s", err)
			}
			return assetPacket, i, nil
		}
	}

	return nil, 0, errors.New("no asset opreturn found in transaction")

}

func IsExtensionPacket(opReturnData []byte) bool {
	asset, subdust, err := parsePacketOpReturn(opReturnData)
	return err == nil && len(asset) > 0 || len(subdust) > 0

}
