package extension

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainsAssetPacket(t *testing.T) {
	var empty []byte
	require.Equal(t, false, ContainsAssetPacket(empty))

	// asset packet with no opreturn prefix
	require.Equal(t, false, ContainsAssetPacket([]byte{0x01, 0x02, 0x03}))
	// only opreturn prefix
	require.Equal(t, false, ContainsAssetPacket([]byte{0x6a}))
	// tokenizer error
	require.Equal(t, false, ContainsAssetPacket([]byte{0x6a, 0x01, 0x02, 0x03}))
	// missing ArkadeMagic prefix
	require.Equal(t, false, ContainsAssetPacket([]byte{0x6a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}))
	// include ArkadeMagic prefix, but bad data
	withArkadeMagic := append([]byte{0x6a}, ArkadeMagic...)
	// add 66 bytes to make a valid TLV record
	for i := 0; i < 66; i++ {
		withArkadeMagic = append(withArkadeMagic, 0x00)
	}
	require.Equal(t, false, ContainsAssetPacket(withArkadeMagic))

	// include ArkadeMagic prefix, but bad data length
	withArkadeMagic = []byte{}
	withArkadeMagic = append([]byte{0x6a}, ArkadeMagic...)
	// add bytes that will yield tokenizer error
	for i := 0; i < 67; i++ {
		withArkadeMagic = append(withArkadeMagic, byte(i))
	}
	require.Equal(t, false, ContainsAssetPacket(withArkadeMagic))

	// check valid asset packet
	packet := &AssetPacket{
		Assets: []AssetGroup{controlAsset, normalAsset},
	}
	txOut, err := packet.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, txOut)
	require.Equal(t, true, ContainsAssetPacket(txOut.PkScript))
}
