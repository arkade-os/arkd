package asset_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
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

	t.Run("trailing TLV bytes", func(t *testing.T) {
		// The OP_RETURN TLV stream may contain additional records after the
		// asset data (e.g. type 0x01 Introspector Packet). The asset parser
		// should read only the asset groups and tolerate trailing bytes.
		for _, v := range fixtures.Valid.NewPacketFromTxOut {
			t.Run(v.Name, func(t *testing.T) {
				origScript, err := hex.DecodeString(v.Script)
				require.NoError(t, err)

				origPacket, err := asset.NewPacketFromScript(origScript)
				require.NoError(t, err)

				// Append a fake TLV record (type 0x01) directly to the script's
				// data push by decoding, extending, and re-encoding.
				trailingTLV := []byte{0x01, 0xde, 0xad, 0xbe, 0xef}

				// Extract the raw OP_RETURN data using the tokenizer.
				tokenizer := txscript.MakeScriptTokenizer(0, origScript)
				tokenizer.Next() // skip OP_RETURN opcode
				var rawData []byte
				for tokenizer.Next() {
					rawData = append(rawData, tokenizer.Data()...)
				}
				require.NoError(t, tokenizer.Err())

				// Rebuild script with extended data (original data + trailing TLV).
				extended := make([]byte, len(rawData)+len(trailingTLV))
				copy(extended, rawData)
				copy(extended[len(rawData):], trailingTLV)
				extScript, err := txscript.NewScriptBuilder().
					AddOp(txscript.OP_RETURN).AddData(extended).Script()
				require.NoError(t, err)

				// Must still be recognized as a valid asset packet.
				require.True(t, asset.IsAssetPacket(extScript))

				// Must parse without error despite trailing TLV bytes.
				parsed, err := asset.NewPacketFromScript(extScript)
				require.NoError(t, err)
				require.Equal(t, len(origPacket), len(parsed))
			})
		}
	})

	t.Run("false marker embedded in preceding TLV record", func(t *testing.T) {
		// A TLV record that precedes the real asset record may contain a 0x00
		// byte in its value. If the byte immediately after that 0x00 happens
		// also to be 0x00 (the real asset marker), the scanner performs a
		// trial-parse starting from the embedded 0x00: parseAssetGroups reads
		// varint 0x00 → count=0 → empty Packet, nil error. It therefore
		// returns the wrong candidate, discarding all real asset groups.
		//
		// Layout that triggers the bug (tlvData after ARK magic):
		//   0x02  0x00  |  0x00  [count]  [groups...]
		//   fake type   fake val  real marker  real data
		//
		// The scanner finds the false 0x00 at index 1, trial-parses the
		// remainder (0x00 [count] [groups]) as count=0 groups → success, and
		// returns that slice. newPacketFromReader then reads count=0 and
		// returns an empty Packet instead of the real one.
		for _, v := range fixtures.Valid.NewPacketFromTxOut {
			t.Run(v.Name, func(t *testing.T) {
				origScript, err := hex.DecodeString(v.Script)
				require.NoError(t, err)

				origPacket, err := asset.NewPacketFromScript(origScript)
				require.NoError(t, err)
				require.NotEmpty(t, origPacket, "fixture must have at least one group")

				// Extract raw OP_RETURN payload.
				tokenizer := txscript.MakeScriptTokenizer(0, origScript)
				tokenizer.Next() // skip OP_RETURN opcode
				var rawData []byte
				for tokenizer.Next() {
					rawData = append(rawData, tokenizer.Data()...)
				}
				require.NoError(t, tokenizer.Err())

				// rawData = ARK + 0x00 + <asset groups>
				// Prepend a fake TLV record whose value is 0x00 so that it
				// creates a false "0x00 0x00 …" sequence: the first 0x00 is
				// the embedded value byte, the second 0x00 is the real marker.
				// Type byte 0x02 is arbitrary (just must not be 0x00 itself).
				magic := rawData[:len(asset.ArkadeMagic)]
				assetRecord := rawData[len(asset.ArkadeMagic):] // 0x00 + groups

				fakeTLV := []byte{0x02, 0x00} // type=0x02, 1-byte value=0x00
				injected := make([]byte, 0, len(magic)+len(fakeTLV)+len(assetRecord))
				injected = append(injected, magic...)
				injected = append(injected, fakeTLV...)
				injected = append(injected, assetRecord...)

				injectedScript, err := txscript.NewScriptBuilder().
					AddOp(txscript.OP_RETURN).AddData(injected).Script()
				require.NoError(t, err)

				require.True(t, asset.IsAssetPacket(injectedScript))

				parsed, err := asset.NewPacketFromScript(injectedScript)
				require.NoError(t, err)
				require.Equal(t, len(origPacket), len(parsed),
					"expected %d groups but got %d: false marker consumed real asset data",
					len(origPacket), len(parsed))
			})
		}
	})

	t.Run("arbitrary TLV record order", func(t *testing.T) {
		// The asset marker (0x00) may appear at any position after the ARK
		// magic, not necessarily first.  For example an Introspector record
		// (type 0x01) could precede the asset data.
		for _, v := range fixtures.Valid.NewPacketFromTxOut {
			t.Run(v.Name, func(t *testing.T) {
				origScript, err := hex.DecodeString(v.Script)
				require.NoError(t, err)

				origPacket, err := asset.NewPacketFromScript(origScript)
				require.NoError(t, err)

				// Extract raw OP_RETURN payload.
				tokenizer := txscript.MakeScriptTokenizer(0, origScript)
				tokenizer.Next() // skip OP_RETURN opcode
				var rawData []byte
				for tokenizer.Next() {
					rawData = append(rawData, tokenizer.Data()...)
				}
				require.NoError(t, tokenizer.Err())

				// rawData = ARK + 0x00 + <asset groups>.
				// Rearrange to: ARK + 0x01 <fake introspector> + 0x00 + <asset groups>.
				magic := rawData[:len(asset.ArkadeMagic)]
				assetRecord := rawData[len(asset.ArkadeMagic):] // 0x00 + groups

				fakeIntrospector := []byte{0x01, 0xca, 0xfe}
				reordered := make([]byte, 0, len(magic)+len(fakeIntrospector)+len(assetRecord))
				reordered = append(reordered, magic...)
				reordered = append(reordered, fakeIntrospector...)
				reordered = append(reordered, assetRecord...)

				reorderedScript, err := txscript.NewScriptBuilder().
					AddOp(txscript.OP_RETURN).AddData(reordered).Script()
				require.NoError(t, err)

				require.True(t, asset.IsAssetPacket(reorderedScript))

				parsed, err := asset.NewPacketFromScript(reorderedScript)
				require.NoError(t, err)
				require.Equal(t, len(origPacket), len(parsed))
			})
		}
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
