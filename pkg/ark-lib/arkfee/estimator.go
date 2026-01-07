package arkfee

import (
	"fmt"
	"reflect"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
	"github.com/google/cel-go/cel"
)

type Config struct {
	IntentOffchainInputProgram  string
	IntentOnchainInputProgram   string
	IntentOffchainOutputProgram string
	IntentOnchainOutputProgram  string
}

type program struct {
	cel.Program
	txt string
}

func (p *program) Eval(args map[string]any) (FeeAmount, error) {
	result, _, err := p.Program.Eval(args)
	if err != nil {
		return 0, err
	}
	native, err := result.ConvertToNative(reflect.TypeOf(float64(0)))
	if err != nil {
		return 0, err
	}
	return FeeAmount(native.(float64)), nil
}

type Estimator struct {
	intentOffchainInput  *program
	intentOnchainInput   *program
	intentOffchainOutput *program
	intentOnchainOutput  *program
}

// New parses the intent input and output programs if not empty and returns a new Estimator
func New(config Config) (estimator *Estimator, err error) {
	estimator = &Estimator{}

	if len(config.IntentOffchainInputProgram) > 0 {
		estimator.intentOffchainInput, err = Parse(config.IntentOffchainInputProgram, celenv.IntentOffchainInputEnv)
		if err != nil {
			return
		}
	}
	if len(config.IntentOnchainInputProgram) > 0 {
		estimator.intentOnchainInput, err = Parse(config.IntentOnchainInputProgram, celenv.IntentOnchainInputEnv)
		if err != nil {
			return
		}
	}
	if len(config.IntentOffchainOutputProgram) > 0 {
		estimator.intentOffchainOutput, err = Parse(config.IntentOffchainOutputProgram, celenv.IntentOutputEnv)
		if err != nil {
			return
		}
	}
	if len(config.IntentOnchainOutputProgram) > 0 {
		estimator.intentOnchainOutput, err = Parse(config.IntentOnchainOutputProgram, celenv.IntentOutputEnv)
		if err != nil {
			return
		}
	}

	return
}

// EvalOffchainInput evalutes the fee for a given vtxo input
func (e Estimator) EvalOffchainInput(input OffchainInput) (FeeAmount, error) {
	if e.intentOffchainInput == nil {
		return 0, nil
	}

	return e.intentOffchainInput.Eval(input.toArgs())
}

// EvalOnchainInput evalutes the fee for a given boarding input
func (e Estimator) EvalOnchainInput(input OnchainInput) (FeeAmount, error) {
	if e.intentOnchainInput == nil {
		return 0, nil
	}

	return e.intentOnchainInput.Eval(input.toArgs())
}

// EvalOffchainOutput evalutes the fee for a given vtxo output
func (e Estimator) EvalOffchainOutput(output Output) (FeeAmount, error) {
	if e.intentOffchainOutput == nil {
		return 0, nil
	}

	return e.intentOffchainOutput.Eval(output.toArgs())
}

// EvalOnchainOutput evalutes the fee for a given collaborative exit output
func (e Estimator) EvalOnchainOutput(output Output) (FeeAmount, error) {
	if e.intentOnchainOutput == nil {
		return 0, nil
	}

	return e.intentOnchainOutput.Eval(output.toArgs())
}

// Eval evaluates the fee for a given set of inputs and outputs
func (e Estimator) Eval(
	offchainInputs []OffchainInput, onchainInputs []OnchainInput,
	offchainOutputs, onchainOutputs []Output,
) (FeeAmount, error) {
	fee := FeeAmount(0)

	for _, input := range offchainInputs {
		inputFee, err := e.EvalOffchainInput(input)
		if err != nil {
			return 0, err
		}
		fee += inputFee
	}

	for _, input := range onchainInputs {
		inputFee, err := e.EvalOnchainInput(input)
		if err != nil {
			return 0, err
		}
		fee += inputFee
	}

	for _, output := range offchainOutputs {
		outputFee, err := e.EvalOffchainOutput(output)
		if err != nil {
			return 0, err
		}
		fee += outputFee
	}

	for _, output := range onchainOutputs {
		outputFee, err := e.EvalOnchainOutput(output)
		if err != nil {
			return 0, err
		}
		fee += outputFee
	}

	return fee, nil
}

func Parse(txt string, env *cel.Env) (*program, error) {
	ast, issues := env.Compile(txt)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	if ast.OutputType() != cel.DoubleType {
		return nil, fmt.Errorf("expected return type double, got %v", ast.OutputType())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return &program{txt: txt, Program: prg}, nil
}
