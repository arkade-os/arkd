package arkfee

import (
	"fmt"
	"reflect"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
	"github.com/google/cel-go/cel"
)

type CelProgram struct {
	cel.Program
	txt string
}

type Estimator struct {
	intentInput  *CelProgram
	intentOutput *CelProgram
}

// New parses the intent input and output programs if not empty and returns a new Estimator
func New(intentInputProgram, intentOutputProgram string) (*Estimator, error) {
	estimator := &Estimator{}

	if len(intentInputProgram) > 0 {
		prg, err := parse(intentInputProgram, celenv.IntentInputEnv)
		if err != nil {
			return nil, err
		}
		estimator.intentInput = &CelProgram{txt: intentInputProgram, Program: prg}
	}

	if len(intentOutputProgram) > 0 {
		prg, err := parse(intentOutputProgram, celenv.IntentOutputEnv)
		if err != nil {
			return nil, err
		}
		estimator.intentOutput = &CelProgram{txt: intentOutputProgram, Program: prg}
	}

	return estimator, nil
}

// EvalInputFee evaluates the intentInputProgram with the given parameters
func (e *Estimator) EvalInput(input Input) (FeeAmount, error) {
	if e.intentInput == nil {
		return 0, nil
	}

	result, _, err := e.intentInput.Eval(input.toArgs())
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
	if e.intentOutput == nil {
		return 0, nil
	}

	result, _, err := e.intentOutput.Eval(output.toArgs())
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

func (e *Estimator) IntentInputProgram() string {
	if e.intentInput == nil {
		return ""
	}
	return e.intentInput.txt
}

func (e *Estimator) IntentOutputProgram() string {
	if e.intentOutput == nil {
		return ""
	}
	return e.intentOutput.txt
}

func parse(txt string, env *cel.Env) (cel.Program, error) {
	ast, issues := env.Compile(txt)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	if ast.OutputType() != cel.DoubleType {
		return nil, fmt.Errorf("expected return type double, got %v", ast.OutputType())
	}

	return env.Program(ast)
}
