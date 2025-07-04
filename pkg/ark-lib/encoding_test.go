package arklib_test

import (
	"encoding/hex"
	"testing"

	common "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

func TestAddressEncoding(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			addr              string
			expectedVersion   uint8
			expectedPrefix    string
			expectedUserKey   string
			expectedSignerKey string
		}{
			{
				addr:              "tark1qqellv77udfmr20tun8dvju5vgudpf9vxe8jwhthrkn26fz96pawqfdy8nk05rsmrf8h94j26905e7n6sng8y059z8ykn2j5xcuw4xt846qj6x",
				expectedVersion:   0,
				expectedPrefix:    "tark",
				expectedUserKey:   "0225a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
				expectedSignerKey: "0233ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0",
			},
		}
		for _, f := range fixtures {
			addr, err := common.DecodeAddressV0(f.addr)
			require.NoError(t, err)
			require.NotNil(t, addr)
			require.Equal(t, f.expectedVersion, addr.Version)
			require.Equal(t, f.expectedPrefix, addr.HRP)
			require.Equal(
				t,
				f.expectedUserKey,
				hex.EncodeToString(addr.VtxoTapKey.SerializeCompressed()),
			)
			require.Equal(
				t,
				f.expectedSignerKey,
				hex.EncodeToString(addr.Signer.SerializeCompressed()),
			)

			encoded, err := addr.EncodeV0()
			require.NoError(t, err)
			require.Equal(t, f.addr, encoded)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			addr          string
			expectedError string
		}{
			{
				addr:          "wrongprefix1qt9tfh7c09hlsstzq5y9tzuwyaesrwr8gpy8cn29cxv0flp64958s0n0yd0",
				expectedError: "unknown prefix",
			},
			{
				addr:          "tark1x0lm8hhr2wc6n6lyemtyh9rz8rg2ftpkfun46aca56kjg3ws0tsztfpuanaquxc6faedvjk3tax0575y6perapg3e95654pk8r4fjecs5fyd2",
				expectedError: "invalid address bytes length",
			},
		}
		for _, f := range fixtures {
			t.Run(f.expectedError, func(t *testing.T) {
				addr, err := common.DecodeAddressV0(f.addr)
				require.Contains(t, err.Error(), f.expectedError)
				require.Nil(t, addr)
			})
		}
	})
}
