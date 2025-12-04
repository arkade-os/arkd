package arkfee

import (
	"reflect"

	"github.com/google/cel-go/cel"
)

type Estimator struct {
	intentInputProgram  cel.Program
	intentOutputProgram cel.Program
}

func NewEstimator(intentInputProgram, intentOutputProgram cel.Program) *Estimator {
	return &Estimator{intentInputProgram, intentOutputProgram}
}

// EvalInputFee evaluates the intentInputProgram with the given parameters
func (e *Estimator) EvalInput(input Input) (FeeAmount, error) {
	result, _, err := e.intentInputProgram.Eval(input.toArgs())
	if err != nil {
		return 0, err
	}

	native, err := result.ConvertToNative(reflect.TypeOf(float64(0)))
	if err != nil {
		return 0, err
	}
	return FeeAmount(native.(float64)), nil
}

func (e *Estimator) EvalOutput(output Output) (FeeAmount, error) {
	result, _, err := e.intentOutputProgram.Eval(output.toArgs())
	if err != nil {
		return 0, err
	}

	native, err := result.ConvertToNative(reflect.TypeOf(float64(0)))
	if err != nil {
		return 0, err
	}
	return FeeAmount(native.(float64)), nil
}

func (e *Estimator) Eval(inputs []Input, outputs []Output) (FeeAmount, error) {
	fee := FeeAmount(0)

	for _, input := range inputs {
		inputFee, err := e.EvalInput(input)
		if err != nil {
			return 0, err
		}
		fee += inputFee
	}

	for _, output := range outputs {
		outputFee, err := e.EvalOutput(output)
		if err != nil {
			return 0, err
		}
		fee += outputFee
	}

	return fee, nil
}
