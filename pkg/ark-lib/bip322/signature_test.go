package bip322_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/bip322"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	const fixture = `{
		"message": "1740569444",
		"prevouts": {
			"edb27c7ba0236db2b4913f1e8250d8ec731ad4911002e88b5bf5d7897bce44a4:0": {
				"pkScript": "512090560d48309daff763044cfbed12ec370592c4b5f700cf0ffd81e37b880f222e",
				"value": 100000000
			}
		},
		"signature": "AgAAAAABAh8mbzuD/Z52wTKqGBPiThVoi2HuEdCpSyhDvFHSGk7ZAAAAAAACAEAApETOe4nX9VuL6AIQkdQac+zYUIIeP5G0sm0joHt8su0AAAAAAAIAQAABAAAAAAAAAAABagNAd1BP/DqssDI+BNAdvsv1PfVANZfXaKlc0yVVbaaivk1CywDSKbiy5O2Zw4TOGAxlS2XzqjfEDz4Vf2CrpZ1s2CgDAgBAsnUgDzuoHwRfz7nqkil58m5eba5hP/kZXvm3zk31fhmt8UisQcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wJbUO5tqHN7/0ox/o+uJZaceuwU1uQwWx06r8nf/NYX4A0DVUISUOFZ5QdZf238FptJxE5OYR/NVgEf0g0A5sbVLy92/q21ia/twp88FvUvbicqcOHGgaAmbKluBgmwDtLECKAMCAECydSAPO6gfBF/PueqSKXnybl5trmE/+Rle+bfOTfV+Ga3xSKxBwFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAltQ7m2oc3v/SjH+j64llpx67BTW5DBbHTqvyd/81hfgAAAAA"
	}`

	var fixtureMap map[string]interface{}
	err := json.Unmarshal([]byte(fixture), &fixtureMap)
	require.NoError(t, err)

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	prevoutsMap := fixtureMap["prevouts"].(map[string]interface{})

	for outpointStr, prevoutData := range prevoutsMap {
		outpoint, err := wire.NewOutPointFromString(outpointStr)
		require.NoError(t, err)

		prevoutMap := prevoutData.(map[string]interface{})
		pkScript, err := hex.DecodeString(prevoutMap["pkScript"].(string))
		require.NoError(t, err)

		prevout := &wire.TxOut{
			Value:    int64(prevoutMap["value"].(float64)),
			PkScript: pkScript,
		}

		prevouts[*outpoint] = prevout
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)

	signature, err := bip322.DecodeSignature(fixtureMap["signature"].(string))
	require.NoError(t, err)

	err = signature.Verify(fixtureMap["message"].(string), prevoutFetcher)
	require.NoError(t, err)
}
