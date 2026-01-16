package intent_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/stretchr/testify/require"
)

func TestIntentMessage(t *testing.T) {
	// because messages are JSON encoded, parsing the fixtures test the decoding logic
	fixtures := parseMessageFixtures(t)

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			encoded, err := fixture.Message.Encode()
			require.NoError(t, err)
			require.Equal(t, fixture.Expected, encoded)
		})
	}
}

type messageFixture struct {
	Name     string
	Message  intentMsg
	Expected string
}

// interface only for testing purposes (wrap both Delete and Register messages)
type intentMsg interface {
	Encode() (string, error)
	Decode(string) error
}

type jsonMessageFixture struct {
	Name     string          `json:"name"`
	Message  json.RawMessage `json:"message"`
	Expected string          `json:"expected"`
}

func parseMessageFixtures(t *testing.T) []messageFixture {
	file, err := os.ReadFile("testdata/message_fixtures.json")
	require.NoError(t, err)

	var jsonData []jsonMessageFixture
	err = json.Unmarshal(file, &jsonData)
	require.NoError(t, err)

	fixtures := make([]messageFixture, 0, len(jsonData))
	for _, jsonFixture := range jsonData {
		var baseMsg intent.BaseMessage
		err = json.Unmarshal(jsonFixture.Message, &baseMsg)
		require.NoError(t, err)

		var msg intentMsg
		switch baseMsg.Type {
		case intent.IntentMessageTypeRegister:
			var registerMsg intent.RegisterMessage
			err := registerMsg.Decode(string(jsonFixture.Message))
			require.NoError(t, err)
			msg = &registerMsg
		case intent.IntentMessageTypeDelete:
			var deleteMsg intent.DeleteMessage
			err := deleteMsg.Decode(string(jsonFixture.Message))
			require.NoError(t, err)
			msg = &deleteMsg
		case intent.IntentMessageTypeGetPendingTx:
			var pendingTxMsg intent.GetPendingTxMessage
			err := pendingTxMsg.Decode(string(jsonFixture.Message))
			require.NoError(t, err)
			msg = &pendingTxMsg
		case intent.IntentMessageTypeEstimateFee:
			var estimateFeeMsg intent.EstimateIntentFeeMessage
			err := estimateFeeMsg.Decode(string(jsonFixture.Message))
			require.NoError(t, err)
			msg = &estimateFeeMsg
		default:
			t.Fatalf("unknown message type: %s", baseMsg.Type)
		}

		fixtures = append(fixtures, messageFixture{
			Name:     jsonFixture.Name,
			Message:  msg,
			Expected: jsonFixture.Expected,
		})
	}

	return fixtures
}
