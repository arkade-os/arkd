package intent_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestNewIntent(t *testing.T) {
	validFixtures, invalidFixtures := parseProofFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, fixture := range validFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				proof, err := intent.New(fixture.Message, fixture.Inputs, fixture.Outputs, 0)
				require.NoError(t, err)
				require.NotNil(t, proof)
				require.GreaterOrEqual(t, len(proof.Inputs), 2)
				require.GreaterOrEqual(t, len(proof.Outputs), 1)

				encodedProof, err := proof.B64Encode()
				require.NoError(t, err)
				require.NotEmpty(t, encodedProof)

				require.Equal(t, fixture.Expected, encodedProof)

				require.Equal(t, len(fixture.Outputs) > 0, proof.ContainsOutputs())

				proofInputOutpoints := proof.GetOutpoints()
				require.Len(t, proofInputOutpoints, len(fixture.Inputs))
				for i, input := range fixture.Inputs {
					require.Equal(t, *input.OutPoint, proofInputOutpoints[i])
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, fixture := range invalidFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				proof, err := intent.New(fixture.Message, fixture.Inputs, fixture.Outputs, 0)
				require.Error(t, err)
				require.Nil(t, proof)
				require.ErrorContains(t, err, fixture.ExpectedError)
			})
		}
	})
}

func TestVerifyIntent(t *testing.T) {
	validFixtures, invalidFixtures := parseVerifyFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, fixture := range validFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				err := intent.Verify(fixture.Proof, fixture.Message)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, fixture := range invalidFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				err := intent.Verify(fixture.Proof, fixture.Message)
				require.Error(t, err)
				require.ErrorContains(t, err, fixture.ExpectedError)
			})
		}
	})
}

func TestIntentGetOutpoints(t *testing.T) {
	t.Run("zero inputs", func(t *testing.T) {
		ptxWithZeroInputs := psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{},
			},
		}
		proof := intent.Proof{Packet: ptxWithZeroInputs}
		outpoints := proof.GetOutpoints()
		require.Len(t, outpoints, 0)
	})

	t.Run("one input", func(t *testing.T) {
		ptxWithOneInput := psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{}}},
			},
		}
		proof := intent.Proof{Packet: ptxWithOneInput}
		outpoints := proof.GetOutpoints()
		require.Len(t, outpoints, 0)
	})
}

type proofFixture struct {
	Name     string
	Inputs   []intent.Input
	Outputs  []*wire.TxOut
	Message  string
	Expected string
}

type invalidProofFixture struct {
	Name          string
	Inputs        []intent.Input
	Outputs       []*wire.TxOut
	Message       string
	ExpectedError string
}

type jsonProofFixture struct {
	Name   string `json:"name"`
	Inputs []struct {
		Txid        string `json:"txid"`
		Vout        uint32 `json:"vout"`
		Sequence    uint32 `json:"sequence,omitempty"`
		WitnessUtxo *struct {
			Script string `json:"script"`
			Amount int64  `json:"amount"`
		} `json:"witness_utxo,omitempty"`
	} `json:"inputs"`
	Outputs []struct {
		Script string `json:"script"`
		Amount int64  `json:"amount"`
	} `json:"outputs"`
	Message       string `json:"message"`
	Expected      string `json:"expected"`
	ExpectedError string `json:"expected_error"`
}

type proofFixturesJSON struct {
	Valid   []jsonProofFixture `json:"valid"`
	Invalid []jsonProofFixture `json:"invalid"`
}

func parseProofFixtures(t *testing.T) ([]proofFixture, []invalidProofFixture) {
	file, err := os.ReadFile("testdata/proof_fixtures.json")
	require.NoError(t, err)

	var jsonData proofFixturesJSON
	err = json.Unmarshal(file, &jsonData)
	require.NoError(t, err)

	validFixtures := make([]proofFixture, 0, len(jsonData.Valid))
	for _, jsonFixture := range jsonData.Valid {
		fixture := proofFixture{
			Name:     jsonFixture.Name,
			Message:  jsonFixture.Message,
			Expected: jsonFixture.Expected,
		}

		fixture.Inputs = make([]intent.Input, 0, len(jsonFixture.Inputs))
		for _, jsonInput := range jsonFixture.Inputs {
			txidBytes, err := hex.DecodeString(jsonInput.Txid)
			require.NoError(t, err)
			var txidHash chainhash.Hash
			copy(txidHash[:], txidBytes)

			scriptBytes, err := hex.DecodeString(jsonInput.WitnessUtxo.Script)
			require.NoError(t, err)

			fixture.Inputs = append(fixture.Inputs, intent.Input{
				OutPoint: &wire.OutPoint{
					Hash:  txidHash,
					Index: jsonInput.Vout,
				},
				Sequence: jsonInput.Sequence,
				WitnessUtxo: &wire.TxOut{
					Value:    jsonInput.WitnessUtxo.Amount,
					PkScript: scriptBytes,
				},
			})
		}

		fixture.Outputs = make([]*wire.TxOut, 0, len(jsonFixture.Outputs))
		for _, jsonOutput := range jsonFixture.Outputs {
			scriptBytes, err := hex.DecodeString(jsonOutput.Script)
			require.NoError(t, err)

			fixture.Outputs = append(fixture.Outputs, &wire.TxOut{
				Value:    jsonOutput.Amount,
				PkScript: scriptBytes,
			})
		}

		validFixtures = append(validFixtures, fixture)
	}

	invalidFixtures := make([]invalidProofFixture, 0, len(jsonData.Invalid))
	for _, jsonFixture := range jsonData.Invalid {
		fixture := invalidProofFixture{
			Name:          jsonFixture.Name,
			Message:       jsonFixture.Message,
			ExpectedError: jsonFixture.ExpectedError,
		}

		fixture.Inputs = make([]intent.Input, 0, len(jsonFixture.Inputs))
		for _, jsonInput := range jsonFixture.Inputs {
			input := intent.Input{
				Sequence: jsonInput.Sequence,
			}

			if len(jsonInput.Txid) > 0 {
				txidBytes, err := hex.DecodeString(jsonInput.Txid)
				require.NoError(t, err)
				var txidHash chainhash.Hash
				copy(txidHash[:], txidBytes)
				input.OutPoint = &wire.OutPoint{
					Hash:  txidHash,
					Index: jsonInput.Vout,
				}
			}

			if jsonInput.WitnessUtxo != nil {
				scriptBytes, err := hex.DecodeString(jsonInput.WitnessUtxo.Script)
				require.NoError(t, err)
				input.WitnessUtxo = &wire.TxOut{
					Value:    jsonInput.WitnessUtxo.Amount,
					PkScript: scriptBytes,
				}
			}
			fixture.Inputs = append(fixture.Inputs, input)
		}

		fixture.Outputs = make([]*wire.TxOut, 0, len(jsonFixture.Outputs))
		for _, jsonOutput := range jsonFixture.Outputs {
			scriptBytes, err := hex.DecodeString(jsonOutput.Script)
			require.NoError(t, err)

			fixture.Outputs = append(fixture.Outputs, &wire.TxOut{
				Value:    jsonOutput.Amount,
				PkScript: scriptBytes,
			})
		}

		invalidFixtures = append(invalidFixtures, fixture)
	}
	return validFixtures, invalidFixtures
}

type verifyFixture struct {
	Name          string `json:"name"`
	Proof         string `json:"proof"`
	Message       string `json:"message"`
	ExpectedError string `json:"expected_error"`
}

type verifyFixturesJSON struct {
	Valid   []verifyFixture `json:"valid"`
	Invalid []verifyFixture `json:"invalid"`
}

func parseVerifyFixtures(t *testing.T) ([]verifyFixture, []verifyFixture) {
	file, err := os.ReadFile("testdata/verify_fixtures.json")
	require.NoError(t, err)

	var jsonData verifyFixturesJSON
	err = json.Unmarshal(file, &jsonData)
	require.NoError(t, err)

	return jsonData.Valid, jsonData.Invalid
}
