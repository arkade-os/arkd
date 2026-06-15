package txfilter_test

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/arkade-os/arkd/internal/interface/grpc/handlers/txfilter"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/valid.json
var validTestdataJSON []byte

//go:embed testdata/invalid.json
var invalidTestdataJSON []byte

func TestParseInvalid(t *testing.T) {
	data := loadInvalidTestData(t)
	for _, tc := range data.InvalidExpressions {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := txfilter.Parse(tc.Expression)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.Err)
		})
	}
}

func TestFilterEval(t *testing.T) {
	data := loadValidTestData(t)
	for _, tc := range data.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f, err := txfilter.Parse(tc.Expression)
			require.NoError(t, err)

			got, err := f.Eval(tc.Tx)
			require.NoError(t, err)
			require.Equal(t, tc.Expected, got)
		})
	}
}

type validTestData struct {
	Cases []evalCase `json:"cases"`
}

type evalCase struct {
	Name       string      `json:"name"`
	Expression string      `json:"expression"`
	Tx         txfilter.Tx `json:"tx"`
	Expected   bool        `json:"expected"`
}

type invalidTestData struct {
	InvalidExpressions []invalidExpression `json:"invalidExpressions"`
}

type invalidExpression struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
	Err        string `json:"err"`
}

func loadValidTestData(t *testing.T) *validTestData {
	t.Helper()
	var data validTestData
	require.NoError(t, json.Unmarshal(validTestdataJSON, &data))
	return &data
}

func loadInvalidTestData(t *testing.T) *invalidTestData {
	t.Helper()
	var data invalidTestData
	require.NoError(t, json.Unmarshal(invalidTestdataJSON, &data))
	return &data
}
