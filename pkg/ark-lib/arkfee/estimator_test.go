package arkfee_test

import (
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/stretchr/testify/require"
)

func TestNewInvalid(t *testing.T) {
	data := loadInvalidTestData(t)

	for _, testCase := range data.InvalidConfigs {
		t.Run(testCase.Name, func(t *testing.T) {
			config := arkfee.Config{
				IntentOffchainInputProgram:  testCase.Config.OffchainInputProgram,
				IntentOnchainInputProgram:   testCase.Config.OnchainInputProgram,
				IntentOffchainOutputProgram: testCase.Config.OffchainOutputProgram,
				IntentOnchainOutputProgram:  testCase.Config.OnchainOutputProgram,
			}

			_, err := arkfee.New(config)
			require.Error(t, err)
			require.ErrorContains(t, err, testCase.Err)
		})
	}
}

func TestEvalOffchainInput(t *testing.T) {
	t.Run("should return 0 if no program is set", func(t *testing.T) {
		estimator, err := arkfee.New(arkfee.Config{})
		require.NoError(t, err)
		require.NotNil(t, estimator)

		result, err := estimator.EvalOffchainInput(arkfee.OffchainInput{})
		require.NoError(t, err)
		require.Equal(t, arkfee.FeeAmount(0), result)
	})

	data := loadTestData(t)

	for _, fixture := range data.EvalOffchainInput {
		t.Run(fixture.Name, func(t *testing.T) {
			estimator, err := arkfee.New(arkfee.Config{
				IntentOffchainInputProgram: fixture.Program,
			})
			require.NoError(t, err)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.Cases {
				t.Run(testCase.Name, func(t *testing.T) {
					input := convertJSONInput(testCase.Input)
					result, err := estimator.EvalOffchainInput(input)
					require.NoError(t, err)
					require.Equal(t, arkfee.FeeAmount(testCase.Expected), result)
				})
			}
		})
	}
}

func TestEvalOnchainInput(t *testing.T) {
	t.Run("should return 0 if no program is set", func(t *testing.T) {
		estimator, err := arkfee.New(arkfee.Config{})
		require.NoError(t, err)
		require.NotNil(t, estimator)

		result, err := estimator.EvalOnchainInput(arkfee.OnchainInput{})
		require.NoError(t, err)
		require.Equal(t, arkfee.FeeAmount(0), result)
	})

	data := loadTestData(t)

	for _, fixture := range data.EvalOnchainInput {
		t.Run(fixture.Name, func(t *testing.T) {
			estimator, err := arkfee.New(arkfee.Config{
				IntentOnchainInputProgram: fixture.Program,
			})
			require.NoError(t, err)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.Cases {
				t.Run(testCase.Name, func(t *testing.T) {
					var jOnchainInput jsonOnchainInput
					// Convert jsonInput to jsonOnchainInput (only amount field)
					jOnchainInput.Amount = testCase.Input.Amount
					input := convertJSONOnchainInput(jOnchainInput)
					result, err := estimator.EvalOnchainInput(input)
					require.NoError(t, err)
					require.Equal(t, arkfee.FeeAmount(testCase.Expected), result)
				})
			}
		})
	}
}

func TestEvalOffchainOutput(t *testing.T) {
	t.Run("should return 0 if no program is set", func(t *testing.T) {
		estimator, err := arkfee.New(arkfee.Config{})
		require.NoError(t, err)
		require.NotNil(t, estimator)

		result, err := estimator.EvalOffchainOutput(arkfee.Output{})
		require.NoError(t, err)
		require.Equal(t, arkfee.FeeAmount(0), result)
	})

	data := loadTestData(t)

	for _, fixture := range data.EvalOffchainOutput {
		t.Run(fixture.Name, func(t *testing.T) {
			estimator, err := arkfee.New(arkfee.Config{
				IntentOffchainOutputProgram: fixture.Program,
			})
			require.NoError(t, err)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.Cases {
				t.Run(testCase.Name, func(t *testing.T) {
					output := convertJSONOutput(testCase.Output)
					result, err := estimator.EvalOffchainOutput(output)
					require.NoError(t, err)
					require.Equal(t, arkfee.FeeAmount(testCase.Expected), result)
				})
			}
		})
	}
}

func TestEvalOnchainOutput(t *testing.T) {
	t.Run("should return 0 if no program is set", func(t *testing.T) {
		estimator, err := arkfee.New(arkfee.Config{})
		require.NoError(t, err)
		require.NotNil(t, estimator)

		result, err := estimator.EvalOnchainOutput(arkfee.Output{})
		require.NoError(t, err)
		require.Equal(t, arkfee.FeeAmount(0), result)
	})

	data := loadTestData(t)

	for _, fixture := range data.EvalOnchainOutput {
		t.Run(fixture.Name, func(t *testing.T) {
			estimator, err := arkfee.New(arkfee.Config{
				IntentOnchainOutputProgram: fixture.Program,
			})
			require.NoError(t, err)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.Cases {
				t.Run(testCase.Name, func(t *testing.T) {
					output := convertJSONOutput(testCase.Output)
					result, err := estimator.EvalOnchainOutput(output)
					require.NoError(t, err)
					require.Equal(t, arkfee.FeeAmount(testCase.Expected), result)
				})
			}
		})
	}
}

func TestEval(t *testing.T) {
	data := loadTestData(t)

	for _, fixture := range data.Eval {
		t.Run(fixture.Name, func(t *testing.T) {
			estimator, err := arkfee.New(arkfee.Config{
				IntentOffchainInputProgram:  fixture.OffchainInputProgram,
				IntentOnchainInputProgram:   fixture.OnchainInputProgram,
				IntentOffchainOutputProgram: fixture.OffchainOutputProgram,
				IntentOnchainOutputProgram:  fixture.OnchainOutputProgram,
			})
			require.NoError(t, err)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.Cases {
				t.Run(testCase.Name, func(t *testing.T) {
					offchainInputs := make([]arkfee.OffchainInput, len(testCase.OffchainInputs))
					for i, jInput := range testCase.OffchainInputs {
						offchainInputs[i] = convertJSONInput(jInput)
					}

					onchainInputs := make([]arkfee.OnchainInput, len(testCase.OnchainInputs))
					for i, jInput := range testCase.OnchainInputs {
						onchainInputs[i] = convertJSONOnchainInput(jInput)
					}

					offchainOutputs := make([]arkfee.Output, len(testCase.OffchainOutputs))
					for i, jOutput := range testCase.OffchainOutputs {
						offchainOutputs[i] = convertJSONOutput(jOutput)
					}

					onchainOutputs := make([]arkfee.Output, len(testCase.OnchainOutputs))
					for i, jOutput := range testCase.OnchainOutputs {
						onchainOutputs[i] = convertJSONOutput(jOutput)
					}

					result, err := estimator.Eval(offchainInputs, onchainInputs, offchainOutputs, onchainOutputs)
					require.NoError(t, err)
					require.Equal(t, arkfee.FeeAmount(testCase.Expected), result)
				})
			}
		})
	}
}

//go:embed testdata/valid.json
var testdataJSON []byte

//go:embed testdata/invalid.json
var invalidTestdataJSON []byte

type jsonTestData struct {
	EvalOffchainInput  []jsonInputFixture  `json:"evalOffchainInput"`
	EvalOnchainInput   []jsonInputFixture  `json:"evalOnchainInput"`
	EvalOffchainOutput []jsonOutputFixture `json:"evalOffchainOutput"`
	EvalOnchainOutput  []jsonOutputFixture `json:"evalOnchainOutput"`
	Eval               []jsonEvalFixture   `json:"eval"`
}

type jsonInputFixture struct {
	Name    string          `json:"name"`
	Program string          `json:"program"`
	Cases   []jsonInputCase `json:"cases"`
}

type jsonInputCase struct {
	Name     string    `json:"name"`
	Input    jsonInput `json:"input"`
	Expected float64   `json:"expected"`
}

type jsonInput struct {
	Amount              uint64  `json:"amount,omitempty"`
	BirthOffsetSeconds  *int64  `json:"birthOffsetSeconds,omitempty"`
	ExpiryOffsetSeconds *int64  `json:"expiryOffsetSeconds,omitempty"`
	Type                string  `json:"type,omitempty"`
	Weight              float64 `json:"weight,omitempty"`
}

type jsonOnchainInput struct {
	Amount uint64 `json:"amount,omitempty"`
}

type jsonOutputFixture struct {
	Name    string           `json:"name"`
	Program string           `json:"program"`
	Cases   []jsonOutputCase `json:"cases"`
}

type jsonOutputCase struct {
	Name     string     `json:"name"`
	Output   jsonOutput `json:"output"`
	Expected float64    `json:"expected"`
}

type jsonOutput struct {
	Amount uint64 `json:"amount,omitempty"`
	Script string `json:"script,omitempty"`
}

type jsonEvalFixture struct {
	Name                  string         `json:"name"`
	OffchainInputProgram  string         `json:"offchainInputProgram,omitempty"`
	OnchainInputProgram   string         `json:"onchainInputProgram,omitempty"`
	OffchainOutputProgram string         `json:"offchainOutputProgram,omitempty"`
	OnchainOutputProgram  string         `json:"onchainOutputProgram,omitempty"`
	Cases                 []jsonEvalCase `json:"cases"`
}

type jsonEvalCase struct {
	Name            string             `json:"name"`
	OffchainInputs  []jsonInput        `json:"offchainInputs,omitempty"`
	OnchainInputs   []jsonOnchainInput `json:"onchainInputs,omitempty"`
	OffchainOutputs []jsonOutput       `json:"offchainOutputs,omitempty"`
	OnchainOutputs  []jsonOutput       `json:"onchainOutputs,omitempty"`
	Expected        float64            `json:"expected"`
}

func loadTestData(t *testing.T) *jsonTestData {
	var data jsonTestData
	err := json.Unmarshal(testdataJSON, &data)
	require.NoError(t, err)
	return &data
}

func convertJSONInput(j jsonInput) arkfee.OffchainInput {
	input := arkfee.OffchainInput{
		Amount: j.Amount,
		Weight: j.Weight,
		Type:   arkfee.VtxoType(j.Type),
	}

	now := time.Now()
	if j.BirthOffsetSeconds != nil {
		input.Birth = now.Add(time.Duration(*j.BirthOffsetSeconds) * time.Second)
	}
	if j.ExpiryOffsetSeconds != nil {
		input.Expiry = now.Add(time.Duration(*j.ExpiryOffsetSeconds) * time.Second)
	}

	return input
}

func convertJSONOutput(j jsonOutput) arkfee.Output {
	return arkfee.Output{
		Amount: j.Amount,
		Script: j.Script,
	}
}

func convertJSONOnchainInput(j jsonOnchainInput) arkfee.OnchainInput {
	return arkfee.OnchainInput{
		Amount: j.Amount,
	}
}

type jsonInvalidTestData struct {
	InvalidConfigs []jsonInvalidConfig `json:"invalidConfigs"`
}

type jsonInvalidConfig struct {
	Name   string     `json:"name"`
	Config jsonConfig `json:"config"`
	Err    string     `json:"err"`
}

type jsonConfig struct {
	OffchainInputProgram  string `json:"offchainInputProgram,omitempty"`
	OnchainInputProgram   string `json:"onchainInputProgram,omitempty"`
	OffchainOutputProgram string `json:"offchainOutputProgram,omitempty"`
	OnchainOutputProgram  string `json:"onchainOutputProgram,omitempty"`
}

func loadInvalidTestData(t *testing.T) *jsonInvalidTestData {
	var data jsonInvalidTestData
	err := json.Unmarshal(invalidTestdataJSON, &data)
	require.NoError(t, err)
	return &data
}
