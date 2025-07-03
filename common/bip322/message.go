package bip322

import (
	"encoding/json"
	"fmt"
)

type IntentMessageType string

const (
	IntentMessageTypeRegister IntentMessageType = "register"
	IntentMessageTypeDelete   IntentMessageType = "delete"
)

type BaseIntentMessage struct {
	Type IntentMessageType `json:"type"`
}

type IntentMessage struct {
	BaseIntentMessage
	// InputTapTrees is the list of taproot trees associated with the spent inputs
	// the index of the taproot tree in the list corresponds to the index of the input + 1
	// (we ignore the first bip322 input, as it is duplicate of the second one)
	InputTapTrees []string `json:"input_tap_trees"`
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

func (m IntentMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m *IntentMessage) Decode(data string) error {
	if err := json.Unmarshal([]byte(data), m); err != nil {
		return err
	}

	if m.Type != IntentMessageTypeRegister {
		return fmt.Errorf("invalid intent message type: %s", m.Type)
	}

	return nil
}

type DeleteIntentMessage struct {
	BaseIntentMessage
	// ExpireAt is the timestamp (in seconds) at which the proof should be considered invalid
	// if set to 0, the proof will be considered valid indefinitely
	ExpireAt int64 `json:"expire_at"`
}

func (m DeleteIntentMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m *DeleteIntentMessage) Decode(data string) error {
	if err := json.Unmarshal([]byte(data), m); err != nil {
		return err
	}

	if m.Type != IntentMessageTypeDelete {
		return fmt.Errorf("invalid intent message type: %s", m.Type)
	}

	return nil
}
