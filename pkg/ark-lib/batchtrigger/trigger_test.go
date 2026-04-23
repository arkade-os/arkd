package batchtrigger_test

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/batchtrigger"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/valid.json
var validJSON []byte

//go:embed testdata/invalid.json
var invalidJSON []byte

type validTestData struct {
	Cases []validCase `json:"cases"`
}

type validCase struct {
	Name     string      `json:"name"`
	Program  string      `json:"program"`
	Context  jsonContext `json:"context"`
	Expected bool        `json:"expected"`
}

type jsonContext struct {
	IntentsCount        int64  `json:"intents_count,omitempty"`
	CurrentFeerate      uint64 `json:"current_feerate,omitempty"`
	TimeSinceLastBatch  int64  `json:"time_since_last_batch,omitempty"`
	BoardingInputsCount int64  `json:"boarding_inputs_count,omitempty"`
	TotalBoardingAmount uint64 `json:"total_boarding_amount,omitempty"`
	TotalIntentFees     uint64 `json:"total_intent_fees,omitempty"`
}

func (j jsonContext) toContext() batchtrigger.Context {
	return batchtrigger.Context{
		IntentsCount:        j.IntentsCount,
		CurrentFeerate:      j.CurrentFeerate,
		TimeSinceLastBatch:  j.TimeSinceLastBatch,
		BoardingInputsCount: j.BoardingInputsCount,
		TotalBoardingAmount: j.TotalBoardingAmount,
		TotalIntentFees:     j.TotalIntentFees,
	}
}

type invalidTestData struct {
	InvalidConfigs []invalidCase `json:"invalidConfigs"`
}

type invalidCase struct {
	Name    string `json:"name"`
	Program string `json:"program"`
	Err     string `json:"err"`
}

func TestNewEmpty(t *testing.T) {
	tr, err := batchtrigger.New("")
	require.NoError(t, err)
	require.Nil(t, tr)
}

func TestNilTriggerAlwaysAllows(t *testing.T) {
	var tr *batchtrigger.Trigger
	ok, err := tr.Eval(batchtrigger.Context{})
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, tr.Source())
}

func TestSource(t *testing.T) {
	src := "intents_count >= 1.0"
	tr, err := batchtrigger.New(src)
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.Equal(t, src, tr.Source())
}

func TestParseInvalid(t *testing.T) {
	var data invalidTestData
	require.NoError(t, json.Unmarshal(invalidJSON, &data))
	require.NotEmpty(t, data.InvalidConfigs)

	for _, tc := range data.InvalidConfigs {
		t.Run(tc.Name, func(t *testing.T) {
			tr, err := batchtrigger.New(tc.Program)
			require.Error(t, err)
			require.Nil(t, tr)
			require.ErrorContains(t, err, tc.Err)
		})
	}
}

func TestEvalValid(t *testing.T) {
	var data validTestData
	require.NoError(t, json.Unmarshal(validJSON, &data))
	require.NotEmpty(t, data.Cases)

	for _, tc := range data.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			tr, err := batchtrigger.New(tc.Program)
			require.NoError(t, err)
			require.NotNil(t, tr)

			got, err := tr.Eval(tc.Context.toContext())
			require.NoError(t, err)
			require.Equal(t, tc.Expected, got)
		})
	}
}

func TestEvalAllVariablesAccessible(t *testing.T) {
	// Ensures every declared CEL variable can be referenced without an
	// "undeclared reference" error.
	prog := "intents_count >= 0.0 && " +
		"current_feerate >= 0.0 && " +
		"time_since_last_batch >= 0.0 && " +
		"boarding_inputs_count >= 0.0 && " +
		"total_boarding_amount >= 0.0 && " +
		"total_intent_fees >= 0.0"
	tr, err := batchtrigger.New(prog)
	require.NoError(t, err)
	require.NotNil(t, tr)

	ok, err := tr.Eval(batchtrigger.Context{})
	require.NoError(t, err)
	require.True(t, ok)
}
