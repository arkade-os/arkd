// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package arkade

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestOpcodeDisasm tests the print function for all opcodes in both the oneline
// and full modes to ensure it provides the expected disassembly.
func TestOpcodeDisasm(t *testing.T) {
	t.Parallel()

	// First, test the oneline disassembly.

	// The expected strings for the data push opcodes are replaced in the
	// test loops below since they involve repeating bytes.  Also, the
	// OP_NOP# and OP_UNKNOWN# are replaced below too, since it's easier
	// than manually listing them here.
	oneBytes := []byte{0x01}
	oneStr := "01"
	expectedStrings := [256]string{0x00: "0", 0x4f: "-1",
		0x50: "OP_RESERVED", 0x61: "OP_NOP", 0x62: "OP_VER",
		0x63: "OP_IF", 0x64: "OP_NOTIF", 0x65: "OP_VERIF",
		0x66: "OP_VERNOTIF", 0x67: "OP_ELSE", 0x68: "OP_ENDIF",
		0x69: "OP_VERIFY", 0x6a: "OP_RETURN", 0x6b: "OP_TOALTSTACK",
		0x6c: "OP_FROMALTSTACK", 0x6d: "OP_2DROP", 0x6e: "OP_2DUP",
		0x6f: "OP_3DUP", 0x70: "OP_2OVER", 0x71: "OP_2ROT",
		0x72: "OP_2SWAP", 0x73: "OP_IFDUP", 0x74: "OP_DEPTH",
		0x75: "OP_DROP", 0x76: "OP_DUP", 0x77: "OP_NIP",
		0x78: "OP_OVER", 0x79: "OP_PICK", 0x7a: "OP_ROLL",
		0x7b: "OP_ROT", 0x7c: "OP_SWAP", 0x7d: "OP_TUCK",
		0x7e: "OP_CAT", 0x7f: "OP_SUBSTR", 0x80: "OP_LEFT",
		0x81: "OP_RIGHT", 0x82: "OP_SIZE", 0x83: "OP_INVERT",
		0x84: "OP_AND", 0x85: "OP_OR", 0x86: "OP_XOR",
		0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY", 0x89: "OP_RESERVED1",
		0x8a: "OP_RESERVED2", 0x8b: "OP_1ADD", 0x8c: "OP_1SUB",
		0x8d: "OP_2MUL", 0x8e: "OP_2DIV", 0x8f: "OP_NEGATE",
		0x90: "OP_ABS", 0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL",
		0x93: "OP_ADD", 0x94: "OP_SUB", 0x95: "OP_MUL", 0x96: "OP_DIV",
		0x97: "OP_MOD", 0x98: "OP_LSHIFT", 0x99: "OP_RSHIFT",
		0x9a: "OP_BOOLAND", 0x9b: "OP_BOOLOR", 0x9c: "OP_NUMEQUAL",
		0x9d: "OP_NUMEQUALVERIFY", 0x9e: "OP_NUMNOTEQUAL",
		0x9f: "OP_LESSTHAN", 0xa0: "OP_GREATERTHAN",
		0xa1: "OP_LESSTHANOREQUAL", 0xa2: "OP_GREATERTHANOREQUAL",
		0xa3: "OP_MIN", 0xa4: "OP_MAX", 0xa5: "OP_WITHIN",
		0xa6: "OP_RIPEMD160", 0xa7: "OP_SHA1", 0xa8: "OP_SHA256",
		0xa9: "OP_HASH160", 0xaa: "OP_HASH256", 0xab: "OP_CODESEPARATOR",
		0xac: "OP_CHECKSIG", 0xad: "OP_CHECKSIGVERIFY",
		0xae: "OP_CHECKMULTISIG", 0xaf: "OP_CHECKMULTISIGVERIFY",
		0xfa: "OP_SMALLINTEGER", 0xfb: "OP_PUBKEYS",
		0xfd: "OP_PUBKEYHASH", 0xfe: "OP_PUBKEY",
		0xff: "OP_INVALIDOPCODE", 0xba: "OP_CHECKSIGADD",
		// Add new defined opcodes
		0xc4: "OP_SHA256INITIALIZE", 0xc5: "OP_SHA256UPDATE",
		0xc6: "OP_SHA256FINALIZE", 0xc7: "OP_INSPECTINPUTOUTPOINT",
		0xc9: "OP_INSPECTINPUTVALUE", 0xca: "OP_INSPECTINPUTSCRIPTPUBKEY",
		0xcb: "OP_INSPECTINPUTSEQUENCE", 0xcc: "OP_CHECKSIGFROMSTACK",
		0xcd: "OP_PUSHCURRENTINPUTINDEX", 0xcf: "OP_INSPECTOUTPUTVALUE",
		0xd1: "OP_INSPECTOUTPUTSCRIPTPUBKEY", 0xd2: "OP_INSPECTVERSION",
		0xd3: "OP_INSPECTLOCKTIME", 0xd4: "OP_INSPECTNUMINPUTS",
		0xd5: "OP_INSPECTNUMOUTPUTS", 0xd6: "OP_TXWEIGHT",
		0xd7: "OP_ADD64", 0xd8: "OP_SUB64", 0xd9: "OP_MUL64",
		0xda: "OP_DIV64", 0xdb: "OP_NEG64", 0xdc: "OP_LESSTHAN64",
		0xdd: "OP_LESSTHANOREQUAL64", 0xde: "OP_GREATERTHAN64",
		0xdf: "OP_GREATERTHANOREQUAL64", 0xe0: "OP_SCRIPTNUMTOLE64",
		0xe1: "OP_LE64TOSCRIPTNUM", 0xe2: "OP_LE32TOLE64",
		0xe3: "OP_ECMULSCALARVERIFY", 0xe4: "OP_TWEAKVERIFY",
	}
	for opcodeVal, expectedStr := range expectedStrings {
		var data []byte
		switch {
		// OP_DATA_1 through OP_DATA_65 display the pushed data.
		case opcodeVal >= 0x01 && opcodeVal < 0x4c:
			data = bytes.Repeat(oneBytes, opcodeVal)
			expectedStr = strings.Repeat(oneStr, opcodeVal)

		// OP_PUSHDATA1.
		case opcodeVal == 0x4c:
			data = bytes.Repeat(oneBytes, 1)
			expectedStr = strings.Repeat(oneStr, 1)

		// OP_PUSHDATA2.
		case opcodeVal == 0x4d:
			data = bytes.Repeat(oneBytes, 2)
			expectedStr = strings.Repeat(oneStr, 2)

		// OP_PUSHDATA4.
		case opcodeVal == 0x4e:
			data = bytes.Repeat(oneBytes, 3)
			expectedStr = strings.Repeat(oneStr, 3)

		// OP_1 through OP_16 display the numbers themselves.
		case opcodeVal >= 0x51 && opcodeVal <= 0x60:
			val := byte(opcodeVal - (0x51 - 1))
			data = []byte{val}
			expectedStr = strconv.Itoa(int(val))

		// OP_NOP1 through OP_NOP10.
		case opcodeVal >= 0xb0 && opcodeVal <= 0xb9:
			switch opcodeVal {
			case 0xb1:
				// OP_NOP2 is an alias of OP_CHECKLOCKTIMEVERIFY
				expectedStr = "OP_CHECKLOCKTIMEVERIFY"
			case 0xb2:
				// OP_NOP3 is an alias of OP_CHECKSEQUENCEVERIFY
				expectedStr = "OP_CHECKSEQUENCEVERIFY"
			default:
				val := byte(opcodeVal - (0xb0 - 1))
				expectedStr = "OP_NOP" + strconv.Itoa(int(val))
			}

		// OP_UNKNOWN#.
		case (opcodeVal >= 0xbb && opcodeVal <= 0xc3) || // Unknown range before SHA256 ops
			(opcodeVal == 0xc8) || // Unknown between input inspection ops
			(opcodeVal == 0xce) || // Unknown between input and output ops
			(opcodeVal == 0xd0) || // Unknown between output ops
			(opcodeVal >= 0xe5 && opcodeVal <= 0xf9) || // Unknown range after new ops
			opcodeVal == 0xfc:
			expectedStr = "OP_UNKNOWN" + strconv.Itoa(opcodeVal)
		}

		var buf strings.Builder
		disasmOpcode(&buf, &opcodeArray[opcodeVal], data, true)
		gotStr := buf.String()
		if gotStr != expectedStr {
			t.Errorf("pop.print (opcode %x): Unexpected disasm "+
				"string - got %v, want %v", opcodeVal, gotStr,
				expectedStr)
			continue
		}
	}

	// Now, replace the relevant fields and test the full disassembly.
	expectedStrings[0x00] = "OP_0"
	expectedStrings[0x4f] = "OP_1NEGATE"
	for opcodeVal, expectedStr := range expectedStrings {
		var data []byte
		switch {
		// OP_DATA_1 through OP_DATA_65 display the opcode followed by
		// the pushed data.
		case opcodeVal >= 0x01 && opcodeVal < 0x4c:
			data = bytes.Repeat(oneBytes, opcodeVal)
			expectedStr = fmt.Sprintf("OP_DATA_%d 0x%s", opcodeVal,
				strings.Repeat(oneStr, opcodeVal))

		// OP_PUSHDATA1.
		case opcodeVal == 0x4c:
			data = bytes.Repeat(oneBytes, 1)
			expectedStr = fmt.Sprintf("OP_PUSHDATA1 0x%02x 0x%s",
				len(data), strings.Repeat(oneStr, 1))

		// OP_PUSHDATA2.
		case opcodeVal == 0x4d:
			data = bytes.Repeat(oneBytes, 2)
			expectedStr = fmt.Sprintf("OP_PUSHDATA2 0x%04x 0x%s",
				len(data), strings.Repeat(oneStr, 2))

		// OP_PUSHDATA4.
		case opcodeVal == 0x4e:
			data = bytes.Repeat(oneBytes, 3)
			expectedStr = fmt.Sprintf("OP_PUSHDATA4 0x%08x 0x%s",
				len(data), strings.Repeat(oneStr, 3))

		// OP_1 through OP_16.
		case opcodeVal >= 0x51 && opcodeVal <= 0x60:
			val := byte(opcodeVal - (0x51 - 1))
			data = []byte{val}
			expectedStr = "OP_" + strconv.Itoa(int(val))

		// OP_NOP1 through OP_NOP10.
		case opcodeVal >= 0xb0 && opcodeVal <= 0xb9:
			switch opcodeVal {
			case 0xb1:
				// OP_NOP2 is an alias of OP_CHECKLOCKTIMEVERIFY
				expectedStr = "OP_CHECKLOCKTIMEVERIFY"
			case 0xb2:
				// OP_NOP3 is an alias of OP_CHECKSEQUENCEVERIFY
				expectedStr = "OP_CHECKSEQUENCEVERIFY"
			default:
				val := byte(opcodeVal - (0xb0 - 1))
				expectedStr = "OP_NOP" + strconv.Itoa(int(val))
			}

		// OP_UNKNOWN#.
		case (opcodeVal >= 0xbb && opcodeVal <= 0xc3) || // Unknown range before SHA256 ops
			(opcodeVal == 0xc8) || // Unknown between input inspection ops
			(opcodeVal == 0xce) || // Unknown between input and output ops
			(opcodeVal == 0xd0) || // Unknown between output ops
			(opcodeVal >= 0xe5 && opcodeVal <= 0xf9) || // Unknown range after new ops
			opcodeVal == 0xfc:
			expectedStr = "OP_UNKNOWN" + strconv.Itoa(opcodeVal)
		}

		var buf strings.Builder
		disasmOpcode(&buf, &opcodeArray[opcodeVal], data, false)
		gotStr := buf.String()
		if gotStr != expectedStr {
			t.Errorf("pop.print (opcode %x): Unexpected disasm "+
				"string - got %v, want %v", opcodeVal, gotStr,
				expectedStr)
			continue
		}
	}
}
