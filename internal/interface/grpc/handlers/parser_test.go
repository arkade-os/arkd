package handlers

import (
	"encoding/json"
	"os"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/stretchr/testify/require"
)

type parserFixtures struct {
	ValidProof       string              `json:"valid_proof"`
	ParseGetIntent   parserTestGroup     `json:"parse_get_intent"`
	ParseDeleteIntent parserTestGroup    `json:"parse_delete_intent"`
}

type parserTestGroup struct {
	Valid   []validParserFixture   `json:"valid"`
	Invalid []invalidParserFixture `json:"invalid"`
}

type validParserFixture struct {
	Name            string `json:"name"`
	Message         string `json:"message"`
	ExpectedType    string `json:"expected_type"`
	ExpectedExpireAt int64 `json:"expected_expire_at"`
}

type invalidParserFixture struct {
	Name          string  `json:"name"`
	Proof         *string `json:"proof"`
	Message       *string `json:"message"`
	ExpectedError string  `json:"expected_error"`
}

func loadParserFixtures(t *testing.T) parserFixtures {
	t.Helper()
	file, err := os.ReadFile("testdata/parser_fixtures.json")
	require.NoError(t, err)

	var fixtures parserFixtures
	err = json.Unmarshal(file, &fixtures)
	require.NoError(t, err)
	return fixtures
}

func (f invalidParserFixture) toIntent(validProof string) *arkv1.Intent {
	if f.Proof == nil {
		return nil
	}
	proof := *f.Proof
	if proof == "USE_VALID_PROOF" {
		proof = validProof
	}
	i := &arkv1.Intent{Proof: proof}
	if f.Message != nil {
		i.Message = *f.Message
	}
	return i
}

func TestParseGetIntent(t *testing.T) {
	fixtures := loadParserFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, tc := range fixtures.ParseGetIntent.Valid {
			t.Run(tc.Name, func(t *testing.T) {
				intentProof := &arkv1.Intent{
					Proof:   fixtures.ValidProof,
					Message: tc.Message,
				}

				proof, msg, err := parseGetIntent(intentProof)
				require.NoError(t, err)
				require.NotNil(t, proof)
				require.NotNil(t, msg)
				require.Equal(t, intent.IntentMessageType(tc.ExpectedType), msg.Type)
				require.Equal(t, tc.ExpectedExpireAt, msg.ExpireAt)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range fixtures.ParseGetIntent.Invalid {
			t.Run(tc.Name, func(t *testing.T) {
				intentProof := tc.toIntent(fixtures.ValidProof)

				_, _, err := parseGetIntent(intentProof)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.ExpectedError)
			})
		}
	})
}

func TestParseDeleteIntent(t *testing.T) {
	fixtures := loadParserFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, tc := range fixtures.ParseDeleteIntent.Valid {
			t.Run(tc.Name, func(t *testing.T) {
				intentProof := &arkv1.Intent{
					Proof:   fixtures.ValidProof,
					Message: tc.Message,
				}

				proof, msg, err := parseDeleteIntent(intentProof)
				require.NoError(t, err)
				require.NotNil(t, proof)
				require.NotNil(t, msg)
				require.Equal(t, intent.IntentMessageType(tc.ExpectedType), msg.Type)
				require.Equal(t, tc.ExpectedExpireAt, msg.ExpireAt)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range fixtures.ParseDeleteIntent.Invalid {
			t.Run(tc.Name, func(t *testing.T) {
				intentProof := tc.toIntent(fixtures.ValidProof)

				_, _, err := parseDeleteIntent(intentProof)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.ExpectedError)
			})
		}
	})
}
