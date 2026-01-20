package extension

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
)

type AssetPacket struct {
	Assets  []AssetGroup
	Version byte
}

func (g *AssetPacket) Encode() (wire.TxOut, error) {
	opReturnPacket := &ExtensionPacket{
		Asset: g,
	}
	return opReturnPacket.Encode()
}

func DecodeOutputToAssetPacket(txOut wire.TxOut) (*AssetPacket, error) {
	packet, err := DecodeToExtensionPacket(txOut)
	if err != nil {
		return nil, err
	}
	if packet.Asset == nil {
		return nil, errors.New("missing asset payload")
	}
	return packet.Asset, nil
}

func DeriveAssetPacketFromTx(arkTx wire.MsgTx) (*AssetPacket, int, error) {
	for i, output := range arkTx.TxOut {
		if ContainsAssetPacket(output.PkScript) {
			assetPacket, err := DecodeOutputToAssetPacket(*output)
			if err != nil {
				return nil, 0, fmt.Errorf("error decoding asset Opreturn: %s", err)
			}
			return assetPacket, i, nil
		}
	}

	return nil, 0, errors.New("no asset opreturn found in transaction")
}

func decodeToAssetPacket(payload []byte) (*AssetPacket, error) {
	reader := bytes.NewReader(payload)
	var scratch [8]byte

	assetCount, err := tlv.ReadVarInt(reader, &scratch)
	if err != nil {
		return nil, fmt.Errorf("invalid asset group count: %w", err)
	}

	if assetCount == 0 {
		return nil, errors.New("empty asset group")
	}

	assets := make([]AssetGroup, 0, int(assetCount))
	for i := uint64(0); i < assetCount; i++ {
		var decoded AssetGroup
		if err := decoded.Decode(reader); err != nil {
			return nil, fmt.Errorf("failed to decode asset group %d: %w", i, err)
		}

		assets = append(assets, decoded)
	}

	for i := range assets {
		ag := &assets[i]
		ag.normalizeAssetSlices()
	}

	if reader.Len() != 0 {
		return nil, errors.New("unexpected trailing bytes in asset group payload")
	}

	group := &AssetPacket{
		Assets: assets,
	}

	return group, nil
}
