package intent

import (
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type IntentMessageType string

const (
	IntentMessageTypeRegister     IntentMessageType = "register"
	IntentMessageTypeDelete       IntentMessageType = "delete"
	IntentMessageTypeGetPendingTx IntentMessageType = "get-pending-tx"
	IntentMessageTypeEstimateFee  IntentMessageType = "estimate-intent-fee"
	IntentMessageTypeGetIntent    IntentMessageType = "get-intent"
)

var tagHashMessage = []byte("ark-intent-proof-message")

type BaseMessage struct {
	Type IntentMessageType `json:"type"`
}

type RegisterMessage struct {
	BaseMessage
	// OnchainOutputIndexes specifies what are the outputs in the proof tx
	// that should be considered as onchain by the Ark operator
	OnchainOutputIndexes []int `json:"onchain_output_indexes"`
	// ValidAt is the timestamp (in seconds) at which the proof should be considered valid
	// if set to 0, the proof will be considered valid indefinitely or until ExpireAt is reached
	ValidAt int64 `json:"valid_at"`
	// ExpireAt is the timestamp (in seconds) at which the proof should be considered invalid
	// if set to 0, the proof will be considered valid indefinitely
	ExpireAt int64 `json:"expire_at"`
	// CosignersPublicKeys contains the public keys of the cosigners
	// if the outputs are not registered in the proof or all the outputs are onchain, this field is not required
	// it is required only if one of the outputs is offchain
	CosignersPublicKeys []string `json:"cosigners_public_keys"`
}

func (m RegisterMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m *RegisterMessage) Decode(data string) error {
	if err := json.Unmarshal([]byte(data), m); err != nil {
		return err
	}

	if m.Type != IntentMessageTypeRegister {
		return fmt.Errorf("invalid intent message type: %s", m.Type)
	}

	return nil
}

type EstimateIntentFeeMessage RegisterMessage

func (m EstimateIntentFeeMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m *EstimateIntentFeeMessage) Decode(data string) error {
	if err := json.Unmarshal([]byte(data), m); err != nil {
		return err
	}

	if m.Type != IntentMessageTypeEstimateFee {
		return fmt.Errorf("invalid intent message type: %s", m.Type)
	}

	return nil
}

type DeleteMessage struct {
	BaseMessage
	// ExpireAt is the timestamp (in seconds) at which the proof should be considered invalid
	// if set to 0, the proof will be considered valid indefinitely
	ExpireAt int64 `json:"expire_at"`
}

func (m DeleteMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m DeleteMessage) GetExpireAt() int64      { return m.ExpireAt }
func (m DeleteMessage) GetBaseMessage() BaseMessage { return m.BaseMessage }

func (m *DeleteMessage) Decode(data string) error {
	if err := json.Unmarshal([]byte(data), m); err != nil {
		return err
	}

	if m.Type != IntentMessageTypeDelete {
		return fmt.Errorf("invalid intent message type: %s", m.Type)
	}

	return nil
}

type GetPendingTxMessage struct {
	BaseMessage
	// ExpireAt is the timestamp (in seconds) at which the proof should be considered invalid
	// if set to 0, the proof will be considered valid indefinitely
	ExpireAt int64 `json:"expire_at"`
}

func (m GetPendingTxMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m *GetPendingTxMessage) Decode(data string) error {
	if err := json.Unmarshal([]byte(data), m); err != nil {
		return err
	}

	if m.Type != IntentMessageTypeGetPendingTx {
		return fmt.Errorf("invalid intent message type: %s", m.Type)
	}

	return nil
}
type GetIntentMessage struct {
	BaseMessage
	// ExpireAt is the timestamp (in seconds) at which the proof should be considered invalid
	// if set to 0, the proof will be considered valid indefinitely
	ExpireAt int64 `json:"expire_at"`
}

func (m GetIntentMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m GetIntentMessage) GetExpireAt() int64      { return m.ExpireAt }
func (m GetIntentMessage) GetBaseMessage() BaseMessage { return m.BaseMessage }

func (m *GetIntentMessage) Decode(data string) error {
	if err := json.Unmarshal([]byte(data), m); err != nil {
		return err
	}

	if m.Type != IntentMessageTypeGetIntent {
		return fmt.Errorf("invalid intent message type: %s", m.Type)
	}

	return nil
}

func hashMessage(message string) []byte {
	tagged := chainhash.TaggedHash(tagHashMessage, []byte(message))
	return tagged[:]
}
