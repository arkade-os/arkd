package asset_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestPacket(t *testing.T) {
	var fixtures packetFixtures
	f, err := os.ReadFile("testdata/packet_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("NewPacket", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewPacket {
				t.Run(v.Name, func(t *testing.T) {
					assets := make([]asset.AssetGroup, 0, len(v.Assets))
					for _, vv := range v.Assets {
						assetGroup, err := asset.NewAssetGroup(vv.parse())
						require.NoError(t, err)
						require.NotNil(t, assetGroup)
						assets = append(assets, *assetGroup)
					}
					packet, err := asset.NewPacket(assets)
					require.NoError(t, err)
					require.NotNil(t, packet)

					got, err := packet.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					gotTxOut, err := packet.TxOut()
					require.NoError(t, err)
					require.NotNil(t, gotTxOut)
					require.Equal(t, v.ExpectedAmount, gotTxOut.Value)
					require.Equal(t, v.ExpectedScript, hex.EncodeToString(gotTxOut.PkScript))

					testPacket, err := asset.NewPacketFromString(v.ExpectedScript)
					require.NoError(t, err)
					require.Equal(t, asset.Packet(assets), testPacket)
				})
			}
		})
		t.Run("NewPacketFromString", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewPacketFromString {
				t.Run(v.Name, func(t *testing.T) {
					packet, err := asset.NewPacketFromString(v.Script)
					require.NoError(t, err)
					require.NotNil(t, packet)

					got, err := packet.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.Script, packet.String())
				})
			}
		})
		t.Run("NewPacketFromTxOut", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewPacketFromTxOut {
				t.Run(v.Name, func(t *testing.T) {
					script, err := hex.DecodeString(v.Script)
					require.NoError(t, err)
					require.NotNil(t, script)
					require.True(t, asset.IsAssetPacket(script))

					packet, err := asset.NewPacketFromTxOut(wire.TxOut{
						PkScript: script,
						Value:    v.Amount},
					)
					require.NoError(t, err)
					require.NotNil(t, packet)

					got, err := packet.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.Script, packet.String())

					testPacket, err := asset.NewPacketFromString(v.Script)
					require.NoError(t, err)
					require.Equal(t, packet, testPacket)
				})
			}
		})

		t.Run("LeafTxPacket", func(t *testing.T) {
			for _, v := range fixtures.Valid.LeafTxPacket {
				t.Run(v.Name, func(t *testing.T) {
					intentTxHash, err := chainhash.NewHashFromStr(v.IntentTxid)
					require.NoError(t, err)
					require.NotNil(t, intentTxHash)

					packet, err := asset.NewPacketFromString(v.Script)
					require.NoError(t, err)
					require.NotEmpty(t, packet)

					leafTxPacket := packet.LeafTxPacket(*intentTxHash)
					require.NotEmpty(t, leafTxPacket)
					require.Equal(t, v.ExpectedLeafTxPacket, leafTxPacket.String())
				})
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("NewPacket", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewPacket {
				t.Run(v.Name, func(t *testing.T) {
					assets := make([]asset.AssetGroup, 0, len(v.Assets))
					for _, vv := range v.Assets {
						assetGroup, err := asset.NewAssetGroup(vv.parse())
						require.NoError(t, err)
						require.NotNil(t, assetGroup)
						assets = append(assets, *assetGroup)
					}
					got, err := asset.NewPacket(assets)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("NewPacketFromString", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewPacketFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewPacketFromString(v.Script)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("NewPacketFromTxOut", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewPacketFromTxOut {
				t.Run(v.Name, func(t *testing.T) {
					script, err := hex.DecodeString(v.Script)
					require.NoError(t, err)

					packet, err := asset.NewPacketFromTxOut(wire.TxOut{
						PkScript: script,
						Value:    v.Amount,
					})
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, packet)
					require.False(t, asset.IsAssetPacket(script))
				})
			}
		})
	})
}

type packetFixtures struct {
	Valid struct {
		NewPacket []struct {
			Name           string                    `json:"name"`
			Assets         []packetValidationFixture `json:"assets"`
			ExpectedAmount int64                     `json:"expectedAmount"`
			ExpectedScript string                    `json:"expectedScript"`
		} `json:"newPacket"`
		NewPacketFromString []struct {
			Name   string `json:"name"`
			Script string `json:"script"`
		} `json:"newPacketFromString"`
		NewPacketFromTxOut []struct {
			Name     string `json:"name"`
			Script   string `json:"script"`
			Amount   int64  `json:"amount"`
			Expected bool   `json:"expected"`
		} `json:"newPacketFromTxOut"`
		LeafTxPacket []struct {
			Name                 string `json:"name"`
			Script               string `json:"script"`
			IntentTxid           string `json:"intentTxid"`
			ExpectedLeafTxPacket string `json:"expectedLeafTxPacket"`
		} `json:"leafTxPacket"`
	} `json:"valid"`
	Invalid struct {
		NewPacket []struct {
			Name          string                    `json:"name"`
			Assets        []packetValidationFixture `json:"assets"`
			ExpectedError string                    `json:"expectedError"`
		} `json:"newPacket"`
		NewPacketFromString []struct {
			Name          string `json:"name"`
			Script        string `json:"script"`
			ExpectedError string `json:"expectedError"`
		} `json:"newPacketFromString"`
		NewPacketFromTxOut []struct {
			Name          string `json:"name"`
			Script        string `json:"script"`
			Amount        int64  `json:"amount"`
			ExpectedError string `json:"expectedError"`
		} `json:"newPacketFromTxOut"`
	} `json:"invalid"`
}

type packetValidationFixture struct {
	AssetId      assetIdFixture       `json:"assetId,omitempty"`
	ControlAsset *assetRefFixture     `json:"controlAsset,omitempty"`
	Metadata     []metadataFixture    `json:"metadata,omitempty"`
	Inputs       []assetInputFixture  `json:"inputs"`
	Outputs      []assetOutputFixture `json:"outputs"`
}

func (f packetValidationFixture) parse() (
	*asset.AssetId, *asset.AssetRef, []asset.AssetInput, []asset.AssetOutput, []asset.Metadata,
) {
	ins := make([]asset.AssetInput, 0, len(f.Inputs))
	for _, in := range f.Inputs {
		ins = append(ins, *in.parse())
	}
	outs := make([]asset.AssetOutput, 0, len(f.Outputs))
	for _, out := range f.Outputs {
		outs = append(outs, *out.parse())
	}
	md := make([]asset.Metadata, 0, len(f.Metadata))
	for _, m := range f.Metadata {
		md = append(md, *m.parse())
	}
	if len(ins) == 0 {
		ins = nil
	}
	if len(outs) == 0 {
		outs = nil
	}
	if len(md) == 0 {
		md = nil
	}
	var ctrlAsset *asset.AssetRef
	if f.ControlAsset != nil {
		ctrlAsset = f.ControlAsset.parse()
	}
	return f.AssetId.parse(), ctrlAsset, ins, outs, md
}
