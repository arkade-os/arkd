package arkfee

import (
	"math"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
)

type FeeAmount float64

func (f FeeAmount) ToSatoshis() int {
	return int(math.Ceil(float64(f)))
}

type InputType string

const (
	InputTypeRecoverable InputType = "recoverable"
	InputTypeVtxo        InputType = "vtxo"
	InputTypeBoarding    InputType = "boarding"
	InputTypeNote        InputType = "note"
)

type Input struct {
	Amount int
	Expiry time.Time
	Birth  time.Time
	Type   InputType
	Weight float64
}

func (i Input) toArgs() map[string]any {
	return map[string]any{
		celenv.AmountVariableName:    float64(i.Amount),
		celenv.ExpiryVariableName:    float64(i.Expiry.Unix()),
		celenv.BirthVariableName:     float64(i.Birth.Unix()),
		celenv.InputTypeVariableName: string(i.Type),
		celenv.WeightVariableName:    i.Weight,
	}
}

type OutputType string

const (
	OutputTypeVtxo    OutputType = "vtxo"
	OutputTypeOnchain OutputType = "onchain"
)

type Output struct {
	Amount int
	Type   OutputType
}

func (o Output) toArgs() map[string]any {
	return map[string]any{
		celenv.AmountVariableName:     float64(o.Amount),
		celenv.OutputTypeVariableName: string(o.Type),
	}
}
