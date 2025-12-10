package arkfee

import (
	"math"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
)

type FeeAmount float64

func (f FeeAmount) ToSatoshis() int64 {
	return int64(math.Ceil(float64(f)))
}

type VtxoType string

const (
	VtxoTypeRecoverable VtxoType = "recoverable"
	VtxoTypeVtxo        VtxoType = "vtxo"
	VtxoTypeNote        VtxoType = "note"
)

type OffchainInput struct {
	Amount uint64
	Expiry time.Time
	Birth  time.Time
	Type   VtxoType
	Weight float64
}

func (i OffchainInput) toArgs() map[string]any {
	args := map[string]any{
		celenv.AmountVariableName:    float64(i.Amount),
		celenv.InputTypeVariableName: string(i.Type),
		celenv.WeightVariableName:    i.Weight,
	}
	if !i.Expiry.IsZero() {
		args[celenv.ExpiryVariableName] = float64(i.Expiry.Unix())
	}
	if !i.Birth.IsZero() {
		args[celenv.BirthVariableName] = float64(i.Birth.Unix())
	}
	return args
}

type OnchainInput struct {
	Amount uint64
}

func (i OnchainInput) toArgs() map[string]any {
	return map[string]any{
		celenv.AmountVariableName: float64(i.Amount),
	}
}

type Output struct {
	Amount uint64
	Script string
}

func (o Output) toArgs() map[string]any {
	return map[string]any{
		celenv.AmountVariableName:       float64(o.Amount),
		celenv.OutputScriptVariableName: o.Script,
	}
}
