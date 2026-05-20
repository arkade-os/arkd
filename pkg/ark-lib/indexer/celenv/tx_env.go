package celenv

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/cel-go/cel"
)

var TxEnv *cel.Env

// MaxEvalCost is the maximum CEL runtime cost permitted for a single tx filter
// evaluation. Programs that exceed this are aborted with a "runtime cost limit
// exceeded" error, which matchesTx treats as "no match". The bound is generous
// enough for chained .contains() calls on multi-kB packet bodies and tight
// enough to kill pathological expressions before they stall the dispatch loop.
const MaxEvalCost uint64 = 1_000_000

func init() {
	var err error
	TxEnv, err = cel.NewEnv(
		tx,
		hasPacketFunction,
	)
	if err != nil {
		panic(err)
	}
}

// Compile parses, type-checks and compiles a CEL expression against TxEnv.
// The expression must yield a bool. Programs are produced with a cost limit
// so a single Eval call cannot consume unbounded CPU.
func Compile(expr string) (cel.Program, error) {
	ast, iss := TxEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("compile %q: %w", expr, iss.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf(
			"compile %q: expression must return bool, got %s", expr, ast.OutputType(),
		)
	}
	return TxEnv.Program(ast, cel.CostLimit(MaxEvalCost))
}

// Eval runs a compiled program against a transaction. It returns true when
// the predicate is satisfied. Errors from the underlying extension parser
// (other than ErrExtensionNotFound) are surfaced.
//
// Callers that evaluate multiple programs against the same transaction should
// build the activation once with BuildActivation and call EvalWithActivation
// for each program to avoid re-parsing the OP_RETURN extension.
func Eval(prg cel.Program, tx *wire.MsgTx) (bool, error) {
	act, err := BuildActivation(tx)
	if err != nil {
		return false, err
	}
	return EvalWithActivation(prg, act)
}

// EvalWithActivation runs a compiled program against a pre-built activation.
func EvalWithActivation(prg cel.Program, act map[string]any) (bool, error) {
	out, _, err := prg.Eval(act)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not yield bool")
	}
	return b, nil
}

// BuildActivation parses the tx's OP_RETURN extension once and produces the
// CEL activation map. Suitable for reuse across many program evaluations on
// the same transaction.
func BuildActivation(tx *wire.MsgTx) (map[string]any, error) {
	txMap := map[string]any{}
	if tx != nil {
		ext, err := extension.NewExtensionFromTx(tx)
		switch {
		case err == nil:
			extMap := make(map[int64]string, len(ext))
			for _, p := range ext {
				data, sErr := p.Serialize()
				if sErr != nil {
					return nil, fmt.Errorf("serialize packet: %w", sErr)
				}
				extMap[int64(p.Type())] = hex.EncodeToString(data)
			}
			txMap["extension"] = extMap
		case errors.Is(err, extension.ErrExtensionNotFound):
			// no extension; leave txMap["extension"] unset so has(tx.extension) is false
		default:
			return nil, fmt.Errorf("parse extension: %w", err)
		}
	}
	return map[string]any{TxVariableName: txMap}, nil
}
