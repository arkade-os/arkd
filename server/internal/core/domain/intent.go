package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type Intent struct {
	Id        string
	Inputs    []Vtxo
	Receivers []Receiver
	Proof     string
	Message   string
}

func NewIntent(proof, message string, inputs []Vtxo) (*Intent, error) {
	intent := &Intent{
		Id:      uuid.New().String(),
		Inputs:  inputs,
		Proof:   proof,
		Message: message,
	}
	if err := intent.validate(true); err != nil {
		return nil, err
	}
	return intent, nil
}

func (i *Intent) AddReceivers(receivers []Receiver) (err error) {
	if i.Receivers == nil {
		i.Receivers = make([]Receiver, 0)
	}
	i.Receivers = append(i.Receivers, receivers...)
	defer func() {
		if err != nil {
			i.Receivers = i.Receivers[:len(i.Receivers)-len(receivers)]
		}
	}()
	err = i.validate(false)
	return
}

func (i Intent) TotalInputAmount() uint64 {
	tot := uint64(0)
	for _, in := range i.Inputs {
		tot += in.Amount
	}
	return tot
}

func (i Intent) TotalOutputAmount() uint64 {
	tot := uint64(0)
	for _, r := range i.Receivers {
		tot += r.Amount
	}
	return tot
}

func (i Intent) validate(ignoreOuts bool) error {
	if len(i.Id) <= 0 {
		return fmt.Errorf("missing id")
	}
	if len(i.Proof) <= 0 {
		return fmt.Errorf("missing proof")
	}
	if len(i.Message) <= 0 {
		return fmt.Errorf("missing message")
	}
	if ignoreOuts {
		return nil
	}

	if len(i.Receivers) <= 0 {
		return fmt.Errorf("missing outputs")
	}
	for _, r := range i.Receivers {
		if len(r.OnchainAddress) <= 0 && len(r.PubKey) <= 0 {
			return fmt.Errorf("missing receiver destination")
		}
		if r.Amount == 0 {
			return fmt.Errorf("missing receiver amount")
		}
	}
	return nil
}

type Receiver struct {
	Amount         uint64
	OnchainAddress string // onchain
	PubKey         string // offchain
}

func (r Receiver) IsOnchain() bool {
	return len(r.OnchainAddress) > 0
}

type Intents []Intent

func (t Intents) CountSpentVtxos() int {
	count := 0
	for _, intent := range t {
		for _, in := range intent.Inputs {
			// Notes and swept vtxos are excluded from this count.
			if !in.RequiresForfeit() {
				continue
			}
			count++
		}
	}
	return count
}

func (t Intents) HaveOnlyOnchainOutput() bool {
	for _, intent := range t {
		for _, r := range intent.Receivers {
			if !r.IsOnchain() {
				return false
			}
		}
	}
	return true
}
