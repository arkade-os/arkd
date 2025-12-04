package arkfee_test

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/stretchr/testify/require"
)

func TestEvalInput(t *testing.T) {
	type testCase struct {
		name     string
		input    arkfee.Input
		expected arkfee.FeeAmount
	}

	type fixture struct {
		name    string
		program string
		cases   []testCase
	}

	fixtures := []fixture{
		{
			name:    "pay zero fee if expires in less than 5 minutes",
			program: "expiry - now() < double(duration('5m').getSeconds()) ? 0.0 : amount / 2.0",
			cases: []testCase{
				{
					name: "far expiry",
					input: arkfee.Input{
						Amount: 10000,
						Birth:  time.Now().Add(-10 * time.Minute),
						Expiry: time.Now().Add(time.Hour),
						Type:   arkfee.InputTypeVtxo,
						Weight: 1.0,
					},
					expected: 5000,
				},
				{
					name: "close expiry",
					input: arkfee.Input{
						Amount: 20000,
						Birth:  time.Now().Add(-10 * time.Minute),
						Expiry: time.Now().Add(2 * time.Minute),
						Type:   arkfee.InputTypeBoarding,
						Weight: 1.0,
					},
					expected: 0,
				},
			},
		},
		{
			name:    "free for recoverable",
			program: "inputType == 'recoverable' ? 0.0 : 200.0",
			cases: []testCase{
				{
					name: "recoverable",
					input: arkfee.Input{
						Type: arkfee.InputTypeRecoverable,
					},
					expected: 0,
				},
				{
					name: "not recoverable",
					input: arkfee.Input{
						Amount: 20000,
						Birth:  time.Now().Add(-10 * time.Minute),
						Expiry: time.Now().Add(2 * time.Minute),
						Type:   arkfee.InputTypeBoarding,
						Weight: 1.0,
					},
					expected: 200,
				},
			},
		},
		{
			name:    "weighted fee (1% of the amount)",
			program: "weight * 0.01 * amount",
			cases: []testCase{
				{
					name: "with 56.3% weight",
					input: arkfee.Input{
						Amount: 10000,
						Weight: 0.563,
					},
					expected: 56.3,
				},
				{
					name: "with 100% weight",
					input: arkfee.Input{
						Amount: 10000,
						Weight: 1.0,
					},
					expected: 100,
				},
				{
					name: "with 0% weight",
					input: arkfee.Input{
						Amount: 10000,
						Weight: 0.0,
					},
					expected: 0,
				},
			},
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			intentInputProgram, err := arkfee.ParseIntentInputProgram(fixture.program)
			require.NoError(t, err)
			estimator := arkfee.NewEstimator(intentInputProgram, nil)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.cases {
				t.Run(testCase.name, func(t *testing.T) {
					result, err := estimator.EvalInput(testCase.input)
					require.NoError(t, err)
					require.Equal(t, testCase.expected, result)
				})
			}
		})
	}
}

func TestEvalOutput(t *testing.T) {
	type testCase struct {
		name     string
		output   arkfee.Output
		expected arkfee.FeeAmount
	}

	type fixture struct {
		name    string
		program string
		cases   []testCase
	}

	fixtures := []fixture{
		{
			name:    "free for vtxo output",
			program: "outputType == 'vtxo' ? 0.0 : 200.0",
			cases: []testCase{
				{
					name: "vtxo output",
					output: arkfee.Output{
						Type: arkfee.OutputTypeVtxo,
					},
					expected: 0,
				},
				{
					name: "onchain output",
					output: arkfee.Output{
						Amount: 10000,
						Type:   arkfee.OutputTypeOnchain,
					},
					expected: 200,
				},
			},
		},
		{
			name:    "collab exit pays 20% of the exited amount",
			program: "outputType == 'onchain' ? amount * 0.2 : 0.0",
			cases: []testCase{
				{
					name: "collab exit",
					output: arkfee.Output{
						Amount: 10000,
						Type:   arkfee.OutputTypeOnchain,
					},
					expected: 2000,
				},
			},
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			intentOutputProgram, err := arkfee.ParseIntentOutputProgram(fixture.program)
			require.NoError(t, err)
			estimator := arkfee.NewEstimator(nil, intentOutputProgram)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.cases {
				t.Run(testCase.name, func(t *testing.T) {
					result, err := estimator.EvalOutput(testCase.output)
					require.NoError(t, err)
					require.Equal(t, testCase.expected, result)
				})
			}
		})
	}
}

func TestEval(t *testing.T) {
	type testCase struct {
		name     string
		inputs   []arkfee.Input
		outputs  []arkfee.Output
		expected arkfee.FeeAmount
	}

	type fixture struct {
		name          string
		inputProgram  string
		outputProgram string
		cases         []testCase
	}

	fixtures := []fixture{
		{
			name:          "fixed fee",
			inputProgram:  "100.0",
			outputProgram: "100.0",
			cases: []testCase{
				{
					name: "simple fee",
					inputs: []arkfee.Input{
						{}, // 1 input
					},
					outputs: []arkfee.Output{
						{}, {}, // 2 outputs
					},
					expected: 300,
				},
			},
		},
		{
			name:          "free for vtxo input",
			inputProgram:  "inputType == 'vtxo' ? 0.0 : 100.0",
			outputProgram: "outputType == 'vtxo' ? 0.0 : 100.0",
			cases: []testCase{
				{
					name: "vtxo input",
					inputs: []arkfee.Input{
						{
							Type: arkfee.InputTypeVtxo,
						},
					},
					outputs: []arkfee.Output{
						{
							Type: arkfee.OutputTypeVtxo,
						},
						{
							Type: arkfee.OutputTypeOnchain,
						}, // 2 outputs
					},
					expected: 100,
				},
			},
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			inputProgram, err := arkfee.ParseIntentInputProgram(fixture.inputProgram)
			require.NoError(t, err)
			outputProgram, err := arkfee.ParseIntentOutputProgram(fixture.outputProgram)
			require.NoError(t, err)
			estimator := arkfee.NewEstimator(inputProgram, outputProgram)
			require.NotNil(t, estimator)

			for _, testCase := range fixture.cases {
				t.Run(testCase.name, func(t *testing.T) {
					result, err := estimator.Eval(testCase.inputs, testCase.outputs)
					require.NoError(t, err)
					require.Equal(t, testCase.expected, result)
				})
			}
		})
	}
}
