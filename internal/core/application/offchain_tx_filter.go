package application

import (
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/interface/grpc/handlers/txfilter"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
)

// ExtractOffchainTxFilter compiles a CEL expression and projects it onto
// the structured OffchainTxFilter so the repository can push the
// constraints to SQL. The empty expression is a no-op and produces the
// zero filter.
//
// Supported expression shapes (combined with AND):
//   - has(tx.extension)
//   - hasPacket(tx.extension, <int>)
//   - tx.extension[<int>] == '<hex>'
//   - tx.extension[<int>] != '<hex>' is NOT supported.
//
// Anything else (OR, NOT, comparisons against non-literal values, etc.)
// causes ExtractOffchainTxFilter to return an error so the caller can
// reject the request with InvalidArgument.
func ExtractOffchainTxFilter(expression string) (domain.OffchainTxFilter, error) {
	out := domain.OffchainTxFilter{}
	if expression == "" {
		return out, nil
	}

	parsedAST, issues := txfilter.TxFilterEnv.Compile(expression)
	if issues.Err() != nil {
		return out, issues.Err()
	}
	if parsedAST.OutputType() != cel.BoolType {
		return out, fmt.Errorf(
			"expected bool expression, got %v", parsedAST.OutputType(),
		)
	}

	root := parsedAST.NativeRep().Expr()
	if err := walkOffchainTxFilter(root, &out); err != nil {
		return out, fmt.Errorf("unsupported filter expression: %w", err)
	}
	return out, nil
}

// walkOffchainTxFilter recurses through a CEL AST collecting the
// recognized structured predicates into f. Any unrecognized node shape
// returns an error.
func walkOffchainTxFilter(e ast.Expr, f *domain.OffchainTxFilter) error {
	switch e.Kind() {
	case ast.SelectKind:
		sel := e.AsSelect()
		if !sel.IsTestOnly() {
			return fmt.Errorf("non-presence select is not supported")
		}
		if sel.FieldName() != "extension" {
			return fmt.Errorf("unsupported presence test on field %q", sel.FieldName())
		}
		if !isTxIdent(sel.Operand()) {
			return fmt.Errorf("presence test must target tx.extension")
		}
		f.WithExtension = true
		return nil

	case ast.CallKind:
		call := e.AsCall()
		switch call.FunctionName() {
		case operators.LogicalAnd:
			for _, arg := range call.Args() {
				if err := walkOffchainTxFilter(arg, f); err != nil {
					return err
				}
			}
			return nil

		case "hasPacket":
			args := call.Args()
			if len(args) != 2 {
				return fmt.Errorf("hasPacket expects two arguments")
			}
			if !isTxExtensionSelect(args[0]) {
				return fmt.Errorf("hasPacket first argument must be tx.extension")
			}
			pt, err := asIntLiteral(args[1])
			if err != nil {
				return fmt.Errorf("hasPacket second argument: %w", err)
			}
			if f.WithPacket == nil {
				f.WithPacket = make(map[int]string)
			}
			if _, ok := f.WithPacket[pt]; !ok {
				f.WithPacket[pt] = ""
			}
			return nil

		case operators.Equals:
			args := call.Args()
			if len(args) != 2 {
				return fmt.Errorf("== expects two arguments")
			}
			pt, hexData, err := parseExtensionEqLiteral(args[0], args[1])
			if err != nil {
				return err
			}
			if _, decodeErr := hex.DecodeString(hexData); decodeErr != nil {
				return fmt.Errorf("tx.extension[%d] value must be hex: %w", pt, decodeErr)
			}
			if f.WithPacket == nil {
				f.WithPacket = make(map[int]string)
			}
			if existing, ok := f.WithPacket[pt]; ok && existing != "" && existing != hexData {
				return fmt.Errorf("conflicting payload constraints for packet %d", pt)
			}
			f.WithPacket[pt] = hexData
			return nil

		default:
			return fmt.Errorf("unsupported function %q", call.FunctionName())
		}

	default:
		return fmt.Errorf("unsupported expression kind %v", e.Kind())
	}
}

// parseExtensionEqLiteral inspects the two sides of an `==` call and, if
// one side is `tx.extension[N]` and the other a string literal, returns
// (N, literal).
func parseExtensionEqLiteral(a, b ast.Expr) (int, string, error) {
	if pt, ok := asExtensionIndex(a); ok {
		s, err := asStringLiteral(b)
		if err != nil {
			return 0, "", fmt.Errorf("right side of ==: %w", err)
		}
		return pt, s, nil
	}
	if pt, ok := asExtensionIndex(b); ok {
		s, err := asStringLiteral(a)
		if err != nil {
			return 0, "", fmt.Errorf("left side of ==: %w", err)
		}
		return pt, s, nil
	}
	return 0, "", fmt.Errorf("== must compare tx.extension[N] to a string literal")
}

// asExtensionIndex matches the `tx.extension[N]` shape and returns N.
func asExtensionIndex(e ast.Expr) (int, bool) {
	if e.Kind() != ast.CallKind {
		return 0, false
	}
	call := e.AsCall()
	if call.FunctionName() != operators.Index {
		return 0, false
	}
	args := call.Args()
	if len(args) != 2 {
		return 0, false
	}
	if !isTxExtensionSelect(args[0]) {
		return 0, false
	}
	pt, err := asIntLiteral(args[1])
	if err != nil {
		return 0, false
	}
	return pt, true
}

// isTxExtensionSelect matches the `tx.extension` field selection.
func isTxExtensionSelect(e ast.Expr) bool {
	if e.Kind() != ast.SelectKind {
		return false
	}
	sel := e.AsSelect()
	if sel.IsTestOnly() {
		return false
	}
	if sel.FieldName() != "extension" {
		return false
	}
	return isTxIdent(sel.Operand())
}

func isTxIdent(e ast.Expr) bool {
	return e.Kind() == ast.IdentKind && e.AsIdent() == "tx"
}

// asIntLiteral extracts a CEL integer literal and range-checks it to
// the packet-type byte range. Returns an error for any other CEL value
// kind or out-of-range integer.
func asIntLiteral(e ast.Expr) (int, error) {
	if e.Kind() != ast.LiteralKind {
		return 0, fmt.Errorf("expected int literal")
	}
	var n int64
	switch v := e.AsLiteral().Value().(type) {
	case int64:
		n = v
	case int:
		n = int64(v)
	case uint64:
		if v > uint64(domain.MaxPacketType) {
			return 0, fmt.Errorf("packet type %d out of range", v)
		}
		n = int64(v)
	default:
		return 0, fmt.Errorf("expected int literal, got %T", v)
	}
	if n < 0 || n > int64(domain.MaxPacketType) {
		return 0, fmt.Errorf(
			"packet type %d out of range (must be 0..%d)",
			n, domain.MaxPacketType,
		)
	}
	return int(n), nil
}

func asStringLiteral(e ast.Expr) (string, error) {
	if e.Kind() != ast.LiteralKind {
		return "", fmt.Errorf("expected string literal")
	}
	v := e.AsLiteral()
	asStr, ok := v.Value().(string)
	if !ok {
		return "", fmt.Errorf("expected string literal, got %T", v.Value())
	}
	return asStr, nil
}
