// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package arkade

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// TestBadPC sets the pc to a deliberately bad result then confirms that Step
// and Disasm fail correctly.
func TestBadPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scriptIdx int
	}{
		{scriptIdx: 2},
		{scriptIdx: 3},
	}

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash: chainhash.Hash([32]byte{
						0xc9, 0x97, 0xa5, 0xe5,
						0x6e, 0x10, 0x41, 0x02,
						0xfa, 0x20, 0x9c, 0x6a,
						0x85, 0x2d, 0xd9, 0x06,
						0x60, 0xa2, 0x0b, 0x2d,
						0x9c, 0x35, 0x24, 0x23,
						0xed, 0xce, 0x25, 0x85,
						0x7f, 0xcd, 0x37, 0x04,
					}),
					Index: 0,
				},
				SignatureScript: mustParseShortForm("NOP"),
				Sequence:        4294967295,
			},
		},
		TxOut: []*wire.TxOut{{
			Value:    1000000000,
			PkScript: nil,
		}},
		LockTime: 0,
	}
	pkScript := mustParseShortForm("NOP")

	for _, test := range tests {
		vm, err := NewEngine(pkScript, tx, 0, 0, nil, nil, -1, nil)
		if err != nil {
			t.Errorf("Failed to create script: %v", err)
		}

		// Set to after all scripts.
		vm.scriptIdx = test.scriptIdx

		// Ensure attempting to step fails.
		_, err = vm.Step()
		if err == nil {
			t.Errorf("Step with invalid pc (%v) succeeds!", test)
			continue
		}

		// Ensure attempting to disassemble the current program counter fails.
		_, err = vm.DisasmPC()
		if err == nil {
			t.Errorf("DisasmPC with invalid pc (%v) succeeds!", test)
		}
	}
}

// TestCheckErrorCondition tests the execute early test in CheckErrorCondition()
// since most code paths are tested elsewhere.
func TestCheckErrorCondition(t *testing.T) {
	t.Parallel()

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash: chainhash.Hash([32]byte{
					0xc9, 0x97, 0xa5, 0xe5,
					0x6e, 0x10, 0x41, 0x02,
					0xfa, 0x20, 0x9c, 0x6a,
					0x85, 0x2d, 0xd9, 0x06,
					0x60, 0xa2, 0x0b, 0x2d,
					0x9c, 0x35, 0x24, 0x23,
					0xed, 0xce, 0x25, 0x85,
					0x7f, 0xcd, 0x37, 0x04,
				}),
				Index: 0,
			},
			SignatureScript: nil,
			Sequence:        4294967295,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000000000,
			PkScript: nil,
		}},
		LockTime: 0,
	}
	pkScript := mustParseShortForm("NOP NOP NOP NOP NOP NOP NOP NOP NOP" +
		" NOP TRUE")

	vm, err := NewEngine(pkScript, tx, 0, 0, nil, nil, 0, nil)
	if err != nil {
		t.Errorf("failed to create script: %v", err)
	}

	for i := 0; i < len(pkScript)-1; i++ {
		done, err := vm.Step()
		if err != nil {
			t.Fatalf("failed to step %dth time: %v", i, err)
		}
		if done {
			t.Fatalf("finished early on %dth time", i)
		}

		err = vm.CheckErrorCondition(false)
		if !txscript.IsErrorCode(err, txscript.ErrScriptUnfinished) {
			t.Fatalf("got unexpected error %v on %dth iteration",
				err, i)
		}
	}
	done, err := vm.Step()
	if err != nil {
		t.Fatalf("final step failed %v", err)
	}
	if !done {
		t.Fatalf("final step isn't done!")
	}

	err = vm.CheckErrorCondition(false)
	if err != nil {
		t.Errorf("unexpected error %v on final check", err)
	}
}

// TestInvalidFlagCombinations ensures the script engine returns the expected
// error when disallowed flag combinations are specified.
func TestInvalidFlagCombinations(t *testing.T) {
	t.Parallel()

	tests := []txscript.ScriptFlags{
		txscript.ScriptVerifyCleanStack,
	}

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash: chainhash.Hash([32]byte{
						0xc9, 0x97, 0xa5, 0xe5,
						0x6e, 0x10, 0x41, 0x02,
						0xfa, 0x20, 0x9c, 0x6a,
						0x85, 0x2d, 0xd9, 0x06,
						0x60, 0xa2, 0x0b, 0x2d,
						0x9c, 0x35, 0x24, 0x23,
						0xed, 0xce, 0x25, 0x85,
						0x7f, 0xcd, 0x37, 0x04,
					}),
					Index: 0,
				},
				SignatureScript: []uint8{OP_NOP},
				Sequence:        4294967295,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    1000000000,
				PkScript: nil,
			},
		},
		LockTime: 0,
	}
	pkScript := []byte{OP_NOP}

	for i, test := range tests {
		_, err := NewEngine(pkScript, tx, 0, test, nil, nil, -1, nil)
		if !txscript.IsErrorCode(err, txscript.ErrInvalidFlags) {
			t.Fatalf("TestInvalidFlagCombinations #%d unexpected "+
				"error: %v", i, err)
		}
	}
}

// TestCheckPubKeyEncoding ensures the internal checkPubKeyEncoding function
// works as expected.
func TestCheckPubKeyEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     []byte
		isValid bool
	}{
		{
			name: "uncompressed ok",
			key: hexToBytes("0411db93e1dcdb8a016b49840f8c53bc1eb68" +
				"a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf" +
				"9744464f82e160bfa9b8b64f9d4c03f999b8643f656b" +
				"412a3"),
			isValid: true,
		},
		{
			name: "compressed ok",
			key: hexToBytes("02ce0b14fb842b1ba549fdd675c98075f12e9" +
				"c510f8ef52bd021a9a1f4809d3b4d"),
			isValid: true,
		},
		{
			name: "compressed ok",
			key: hexToBytes("032689c7c2dab13309fb143e0e8fe39634252" +
				"1887e976690b6b47f5b2a4b7d448e"),
			isValid: true,
		},
		{
			name: "hybrid",
			key: hexToBytes("0679be667ef9dcbbac55a06295ce870b07029" +
				"bfcdb2dce28d959f2815b16f81798483ada7726a3c46" +
				"55da4fbfc0e1108a8fd17b448a68554199c47d08ffb1" +
				"0d4b8"),
			isValid: false,
		},
		{
			name:    "empty",
			key:     nil,
			isValid: false,
		},
	}

	vm := Engine{flags: txscript.ScriptVerifyStrictEncoding}
	for _, test := range tests {
		err := vm.checkPubKeyEncoding(test.key)
		if err != nil && test.isValid {
			t.Errorf("checkSignatureEncoding test '%s' failed "+
				"when it should have succeeded: %v", test.name,
				err)
		} else if err == nil && !test.isValid {
			t.Errorf("checkSignatureEncooding test '%s' succeeded "+
				"when it should have failed", test.name)
		}
	}

}

// TestCheckSignatureEncoding ensures the internal checkSignatureEncoding
// function works as expected.
func TestCheckSignatureEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sig     []byte
		isValid bool
	}{
		{
			name: "valid signature",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: true,
		},
		{
			name:    "empty.",
			sig:     nil,
			isValid: false,
		},
		{
			name: "bad magic",
			sig: hexToBytes("314402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "bad 1st int marker magic",
			sig: hexToBytes("304403204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "bad 2nd int marker",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41032018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "short len",
			sig: hexToBytes("304302204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "long len",
			sig: hexToBytes("304502204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "long X",
			sig: hexToBytes("304402424e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "long Y",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022118152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "short Y",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41021918152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "trailing crap",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d0901"),
			isValid: false,
		},
		{
			name: "X == N ",
			sig: hexToBytes("30440220fffffffffffffffffffffffffffff" +
				"ffebaaedce6af48a03bbfd25e8cd0364141022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "X == N ",
			sig: hexToBytes("30440220fffffffffffffffffffffffffffff" +
				"ffebaaedce6af48a03bbfd25e8cd0364142022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "Y == N",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd410220fffff" +
				"ffffffffffffffffffffffffffebaaedce6af48a03bb" +
				"fd25e8cd0364141"),
			isValid: false,
		},
		{
			name: "Y > N",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd410220fffff" +
				"ffffffffffffffffffffffffffebaaedce6af48a03bb" +
				"fd25e8cd0364142"),
			isValid: false,
		},
		{
			name: "0 len X",
			sig: hexToBytes("302402000220181522ec8eca07de4860a4acd" +
				"d12909d831cc56cbbac4622082221a8768d1d09"),
			isValid: false,
		},
		{
			name: "0 len Y",
			sig: hexToBytes("302402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd410200"),
			isValid: false,
		},
		{
			name: "extra R padding",
			sig: hexToBytes("30450221004e45e16932b8af514961a1d3a1a" +
				"25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181" +
				"522ec8eca07de4860a4acdd12909d831cc56cbbac462" +
				"2082221a8768d1d09"),
			isValid: false,
		},
		{
			name: "extra S padding",
			sig: hexToBytes("304502204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022100181" +
				"522ec8eca07de4860a4acdd12909d831cc56cbbac462" +
				"2082221a8768d1d09"),
			isValid: false,
		},
	}

	vm := Engine{flags: txscript.ScriptVerifyStrictEncoding}
	for _, test := range tests {
		err := vm.checkSignatureEncoding(test.sig)
		if err != nil && test.isValid {
			t.Errorf("checkSignatureEncoding test '%s' failed "+
				"when it should have succeeded: %v", test.name,
				err)
		} else if err == nil && !test.isValid {
			t.Errorf("checkSignatureEncooding test '%s' succeeded "+
				"when it should have failed", test.name)
		}
	}
}

func TestNewOpcodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		valid       bool
		tx          *wire.MsgTx
		txIdx       int
		inputAmount int64
		stack       [][]byte
	}

	type fixture struct {
		name   string
		script *txscript.ScriptBuilder
		cases  []testCase
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{
			Hash:  chainhash.Hash{},
			Index: 0,
		}: {
			Value: 1000000000,
			PkScript: []byte{
				OP_1, OP_DATA_32,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	})

	tests := []fixture{
		{
			name:   "OP_MOD",
			script: txscript.NewScriptBuilder().AddOp(OP_4).AddOp(OP_3).AddOp(OP_MOD).AddOp(OP_1).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name:   "OP_DIV",
			script: txscript.NewScriptBuilder().AddOp(OP_DIV).AddOp(OP_3).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x06}, {0x02}},
				},
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x00}, // Divisor of 0 should fail
						{0x01},
					},
				},
			},
		},
		{
			name:   "OP_MUL",
			script: txscript.NewScriptBuilder().AddOp(OP_MUL).AddOp(OP_6).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x02}, {0x03}}, // 2 * 3 = 6
				},
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x06}, {0x01}}, // 6 * 1 = 6
				},
			},
		},
		{
			name:   "OP_XOR",
			script: txscript.NewScriptBuilder().AddOp(OP_XOR).AddOp(OP_6).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x05}, // 5 (0101)
						{0x03}, // 3 (0011)
						// 5 XOR 3 = 6 (0110)
					},
				},
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x0F}, // 15 (1111)
						{0x09}, // 9  (1001)
						// 15 XOR 9 = 6 (0110)
					},
				},
			},
		},
		{
			name: "OP_CAT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02}).
				AddData([]byte{0x03, 0x04}).
				AddOp(OP_CAT).
				AddData([]byte{0x01, 0x02, 0x03, 0x04}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SUBSTR",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03, 0x04}).
				AddData([]byte{0x01}).
				AddData([]byte{0x02}).
				AddOp(OP_SUBSTR).
				AddData([]byte{0x02, 0x03}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LEFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03}).
				AddData([]byte{0x02}).
				AddOp(OP_LEFT).
				AddData([]byte{0x01, 0x02}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_RIGHT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03}).
				AddData([]byte{0x02}).
				AddOp(OP_RIGHT).
				AddData([]byte{0x02, 0x03}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INVERT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00, 0xFF}).
				AddOp(OP_INVERT).
				AddData([]byte{0xFF, 0x00}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_AND",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06}). // 0110
				AddData([]byte{0x0C}). // 1100
				AddOp(OP_AND).
				AddData([]byte{0x04}). // 0100
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_OR",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x07}). // 0111
				AddData([]byte{0x05}). // 0101
				AddOp(OP_OR).
				AddData([]byte{0x07}). // 0111
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LSHIFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03}). // 0011
				AddData([]byte{0x01}). // Shift by 1
				AddOp(OP_LSHIFT).
				AddData([]byte{0x06}). // 0110 (shifted left by 1)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_RSHIFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06}). // 0110
				AddData([]byte{0x01}). // Shift by 1
				AddOp(OP_RSHIFT).
				AddData([]byte{0x03}). // 0011 (shifted right by 1)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_ADD64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_ADD64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_ADD64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}). // Max positive int64
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_ADD64).
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUALVERIFY),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SUB64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_SUB64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SUB64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}). // Min negative int64 (-9223372036854775808)
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_SUB64).
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUALVERIFY),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_MUL64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_MUL64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 6 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_MUL64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}). // Max positive int64
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_MUL64).
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUALVERIFY),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_DIV64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 6 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_DIV64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_NEG64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_NEG64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}). // -3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_NEG64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}). // Min negative int64
				AddOp(OP_NEG64).
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LESSTHAN64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_LESSTHAN64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LESSTHANOREQUAL64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_LESSTHANOREQUAL64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_GREATERTHAN64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_GREATERTHAN64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_GREATERTHANOREQUAL64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_GREATERTHANOREQUAL64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SCRIPTNUMTOLE64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03}). // ScriptNum 3
				AddOp(OP_SCRIPTNUMTOLE64).
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LE64TOSCRIPTNUM",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_LE64TOSCRIPTNUM).
				AddData([]byte{0x03}). // ScriptNum 3
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LE32TOLE64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00}). // 3 in LE32
				AddOp(OP_LE32TOLE64).
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTOUTPOINT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}). // success flag
				AddOp(OP_INSPECTINPUTOUTPOINT).
				AddData([]byte{0x00}). // Index
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}). // Hash
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTVALUE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTVALUE).
				AddData([]byte{0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00}). // 1000000000 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 1000000000,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSCRIPTPUBKEY",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTSCRIPTPUBKEY).
				AddOp(OP_1). // segwit v1
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{ // witness program
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSEQUENCE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTSEQUENCE).
				AddData([]byte{0xFF, 0xFF, 0xFF, 0xFF}). // Max sequence number
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
								Sequence: 4294967295,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_PUSHCURRENTINPUTINDEX",
			script: txscript.NewScriptBuilder().
				AddOp(OP_PUSHCURRENTINPUTINDEX).
				AddData([]byte{0x00}). // Input index 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTVALUE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTOUTPUTVALUE).
				AddData([]byte{0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00}). // 1000000000 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value:    1000000000,
								PkScript: nil,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTSCRIPTPUBKEY",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY).
				AddOp(OP_1). // Expected scriptPubKey
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value: 0,
								PkScript: []byte{
									OP_1, OP_DATA_32,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTVERSION",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTVERSION).
				AddData([]byte{0x01, 0x00, 0x00, 0x00}). // Version 1 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTLOCKTIME",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTLOCKTIME).
				AddData([]byte{0x00, 0x00, 0x00, 0x00}). // LockTime 0 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						LockTime: 0,
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTNUMINPUTS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMINPUTS).
				AddOp(OP_1). // 1 input
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTNUMOUTPUTS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMOUTPUTS).
				AddData([]byte{0x01}). // 1 output
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value:    0,
								PkScript: nil,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_TXWEIGHT",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXWEIGHT).
				AddData([]byte{0xCC, 0x00, 0x00, 0x00}). // Expected weight 204 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_CHECKSIGFROMSTACK",
			script: txscript.NewScriptBuilder().
				AddData([]byte{ // signature
					0xE9, 0x07, 0x83, 0x1F, 0x80, 0x84, 0x8D, 0x10,
					0x69, 0xA5, 0x37, 0x1B, 0x40, 0x24, 0x10, 0x36,
					0x4B, 0xDF, 0x1C, 0x5F, 0x83, 0x07, 0xB0, 0x08,
					0x4C, 0x55, 0xF1, 0xCE, 0x2D, 0xCA, 0x82, 0x15,
					0x25, 0xF6, 0x6A, 0x4A, 0x85, 0xEA, 0x8B, 0x71,
					0xE4, 0x82, 0xA7, 0x4F, 0x38, 0x2D, 0x2C, 0xE5,
					0xEB, 0xEE, 0xE8, 0xFD, 0xB2, 0x17, 0x2F, 0x47,
					0x7D, 0xF4, 0x90, 0x0D, 0x31, 0x05, 0x36, 0xC0,
				}).
				AddData([]byte{ // message
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddData([]byte{ // public key
					0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
					0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
					0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
					0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9,
				}).
				AddOp(OP_CHECKSIGFROMSTACK),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "SHA256_STREAMING",
			script: txscript.NewScriptBuilder().
				AddData([]byte("Hello")).   // stack = [Hello]
				AddOp(OP_SHA256INITIALIZE). // stack = [shactx(Hello)]
				AddData([]byte(" World")).  // stack = [shactx(Hello), World]
				AddOp(OP_SHA256UPDATE).     // stack = [shactx(Hello+World)]
				AddData([]byte("!")).       // stack = [shactx(Hello+World), !]
				AddOp(OP_SHA256FINALIZE).   // stack = [sha256(Hello+World+!)]
				AddData([]byte{
					0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53,
					0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1, 0xd6, 0x5d,
					0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
					0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
	}

	for _, test := range tests {
		for caseIndex, c := range test.cases {
			t.Run(fmt.Sprintf("%s_%d", test.name, caseIndex), func(tt *testing.T) {
				script, err := test.script.Script()
				if err != nil {
					tt.Errorf("NewEngine failed: %v", err)
				}

				engine, err := NewEngine(
					script,
					c.tx, c.txIdx,
					txscript.StandardVerifyFlags&txscript.ScriptVerifyTaproot,
					txscript.NewSigCache(100),
					txscript.NewTxSigHashes(c.tx, prevoutFetcher),
					c.inputAmount,
					prevoutFetcher,
				)
				if err != nil {
					tt.Errorf("NewEngine failed: %v", err)
				}

				if len(c.stack) > 0 {
					engine.SetStack(c.stack)
				}

				err = engine.Execute()
				if c.valid && err != nil {
					tt.Errorf("Execute failed: %v", err)
				}

				if !c.valid && err == nil {
					tt.Errorf("Execute should have failed")
				}
			})
		}
	}
}

// mustParseShortForm parses the passed short form script and returns the
// resulting bytes.  It panics if an error occurs.  This is only used in the
// tests as a helper since the only way it can fail is if there is an error in
// the test source code.
func mustParseShortForm(script string) []byte {
	s, err := parseShortForm(script)
	if err != nil {
		panic("invalid short form script in test source: err " +
			err.Error() + ", script: " + script)
	}

	return s
}

// shortFormOps holds a map of opcode names to values for use in short form
// parsing.  It is declared here so it only needs to be created once.
var shortFormOps map[string]byte

// parseShortForm parses a string as as used in the Bitcoin Core reference tests
// into the script it came from.
//
// The format used for these tests is pretty simple if ad-hoc:
//   - Opcodes other than the push opcodes and unknown are present as
//     either OP_NAME or just NAME
//   - Plain numbers are made into push operations
//   - Numbers beginning with 0x are inserted into the []byte as-is (so
//     0x14 is OP_DATA_20)
//   - Single quoted strings are pushed as data
//   - Anything else is an error
func parseShortForm(script string) ([]byte, error) {
	// Only create the short form opcode map once.
	if shortFormOps == nil {
		ops := make(map[string]byte)
		for opcodeName, opcodeValue := range OpcodeByName {
			if strings.Contains(opcodeName, "OP_UNKNOWN") {
				continue
			}
			ops[opcodeName] = opcodeValue

			// The opcodes named OP_# can't have the OP_ prefix
			// stripped or they would conflict with the plain
			// numbers.  Also, since OP_FALSE and OP_TRUE are
			// aliases for the OP_0, and OP_1, respectively, they
			// have the same value, so detect those by name and
			// allow them.
			if (opcodeName == "OP_FALSE" || opcodeName == "OP_TRUE") ||
				(opcodeValue != OP_0 && (opcodeValue < OP_1 ||
					opcodeValue > OP_16)) {

				ops[strings.TrimPrefix(opcodeName, "OP_")] = opcodeValue
			}
		}
		shortFormOps = ops
	}

	// Split only does one separator so convert all \n and tab into  space.
	script = strings.Replace(script, "\n", " ", -1)
	script = strings.Replace(script, "\t", " ", -1)
	tokens := strings.Split(script, " ")
	builder := txscript.NewScriptBuilder()

	for _, tok := range tokens {
		if len(tok) == 0 {
			continue
		}
		// if parses as a plain number
		if num, err := strconv.ParseInt(tok, 10, 64); err == nil {
			builder.AddInt64(num)
			continue
		} else if _, err := parseHex(tok); err == nil {
			// Concatenate the bytes manually since the test code
			// intentionally creates scripts that are too large and
			// would cause the builder to error otherwise.
			_, err := builder.Script()
			if err == nil {
				return nil, fmt.Errorf("script too large")
			}
		} else if len(tok) >= 2 &&
			tok[0] == '\'' && tok[len(tok)-1] == '\'' {
			builder.AddFullData([]byte(tok[1 : len(tok)-1]))
		} else if opcode, ok := shortFormOps[tok]; ok {
			builder.AddOp(opcode)
		} else {
			return nil, fmt.Errorf("bad token %q", tok)
		}

	}
	return builder.Script()
}

// parse hex string into a []byte.
func parseHex(tok string) ([]byte, error) {
	if !strings.HasPrefix(tok, "0x") {
		return nil, errors.New("not a hex number")
	}
	return hex.DecodeString(tok[2:])
}
