package arkade

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"math/big"
	"strings"

	//nolint:staticcheck
	"golang.org/x/crypto/ripemd160"
	"modernc.org/mathutil"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// An opcode defines the information related to a txscript opcode.  opfunc, if
// present, is the function to call to perform the opcode on the script.  The
// current script is passed in as a slice with the first member being the opcode
// itself.
type opcode struct {
	value  byte
	name   string
	length int
	opfunc func(*opcode, []byte, *Engine) error
}

// These constants are the values of the official opcodes used on the btc wiki,
// in bitcoin core and in most if not all other references and software related
// to handling BTC scripts.
const (
	OP_0                   = 0x00 // 0
	OP_FALSE               = 0x00 // 0 - AKA OP_0
	OP_DATA_1              = 0x01 // 1
	OP_DATA_2              = 0x02 // 2
	OP_DATA_3              = 0x03 // 3
	OP_DATA_4              = 0x04 // 4
	OP_DATA_5              = 0x05 // 5
	OP_DATA_6              = 0x06 // 6
	OP_DATA_7              = 0x07 // 7
	OP_DATA_8              = 0x08 // 8
	OP_DATA_9              = 0x09 // 9
	OP_DATA_10             = 0x0a // 10
	OP_DATA_11             = 0x0b // 11
	OP_DATA_12             = 0x0c // 12
	OP_DATA_13             = 0x0d // 13
	OP_DATA_14             = 0x0e // 14
	OP_DATA_15             = 0x0f // 15
	OP_DATA_16             = 0x10 // 16
	OP_DATA_17             = 0x11 // 17
	OP_DATA_18             = 0x12 // 18
	OP_DATA_19             = 0x13 // 19
	OP_DATA_20             = 0x14 // 20
	OP_DATA_21             = 0x15 // 21
	OP_DATA_22             = 0x16 // 22
	OP_DATA_23             = 0x17 // 23
	OP_DATA_24             = 0x18 // 24
	OP_DATA_25             = 0x19 // 25
	OP_DATA_26             = 0x1a // 26
	OP_DATA_27             = 0x1b // 27
	OP_DATA_28             = 0x1c // 28
	OP_DATA_29             = 0x1d // 29
	OP_DATA_30             = 0x1e // 30
	OP_DATA_31             = 0x1f // 31
	OP_DATA_32             = 0x20 // 32
	OP_DATA_33             = 0x21 // 33
	OP_DATA_34             = 0x22 // 34
	OP_DATA_35             = 0x23 // 35
	OP_DATA_36             = 0x24 // 36
	OP_DATA_37             = 0x25 // 37
	OP_DATA_38             = 0x26 // 38
	OP_DATA_39             = 0x27 // 39
	OP_DATA_40             = 0x28 // 40
	OP_DATA_41             = 0x29 // 41
	OP_DATA_42             = 0x2a // 42
	OP_DATA_43             = 0x2b // 43
	OP_DATA_44             = 0x2c // 44
	OP_DATA_45             = 0x2d // 45
	OP_DATA_46             = 0x2e // 46
	OP_DATA_47             = 0x2f // 47
	OP_DATA_48             = 0x30 // 48
	OP_DATA_49             = 0x31 // 49
	OP_DATA_50             = 0x32 // 50
	OP_DATA_51             = 0x33 // 51
	OP_DATA_52             = 0x34 // 52
	OP_DATA_53             = 0x35 // 53
	OP_DATA_54             = 0x36 // 54
	OP_DATA_55             = 0x37 // 55
	OP_DATA_56             = 0x38 // 56
	OP_DATA_57             = 0x39 // 57
	OP_DATA_58             = 0x3a // 58
	OP_DATA_59             = 0x3b // 59
	OP_DATA_60             = 0x3c // 60
	OP_DATA_61             = 0x3d // 61
	OP_DATA_62             = 0x3e // 62
	OP_DATA_63             = 0x3f // 63
	OP_DATA_64             = 0x40 // 64
	OP_DATA_65             = 0x41 // 65
	OP_DATA_66             = 0x42 // 66
	OP_DATA_67             = 0x43 // 67
	OP_DATA_68             = 0x44 // 68
	OP_DATA_69             = 0x45 // 69
	OP_DATA_70             = 0x46 // 70
	OP_DATA_71             = 0x47 // 71
	OP_DATA_72             = 0x48 // 72
	OP_DATA_73             = 0x49 // 73
	OP_DATA_74             = 0x4a // 74
	OP_DATA_75             = 0x4b // 75
	OP_PUSHDATA1           = 0x4c // 76
	OP_PUSHDATA2           = 0x4d // 77
	OP_PUSHDATA4           = 0x4e // 78
	OP_1NEGATE             = 0x4f // 79
	OP_RESERVED            = 0x50 // 80
	OP_1                   = 0x51 // 81 - AKA OP_TRUE
	OP_TRUE                = 0x51 // 81
	OP_2                   = 0x52 // 82
	OP_3                   = 0x53 // 83
	OP_4                   = 0x54 // 84
	OP_5                   = 0x55 // 85
	OP_6                   = 0x56 // 86
	OP_7                   = 0x57 // 87
	OP_8                   = 0x58 // 88
	OP_9                   = 0x59 // 89
	OP_10                  = 0x5a // 90
	OP_11                  = 0x5b // 91
	OP_12                  = 0x5c // 92
	OP_13                  = 0x5d // 93
	OP_14                  = 0x5e // 94
	OP_15                  = 0x5f // 95
	OP_16                  = 0x60 // 96
	OP_NOP                 = 0x61 // 97
	OP_VER                 = 0x62 // 98
	OP_IF                  = 0x63 // 99
	OP_NOTIF               = 0x64 // 100
	OP_VERIF               = 0x65 // 101
	OP_VERNOTIF            = 0x66 // 102
	OP_ELSE                = 0x67 // 103
	OP_ENDIF               = 0x68 // 104
	OP_VERIFY              = 0x69 // 105
	OP_RETURN              = 0x6a // 106
	OP_TOALTSTACK          = 0x6b // 107
	OP_FROMALTSTACK        = 0x6c // 108
	OP_2DROP               = 0x6d // 109
	OP_2DUP                = 0x6e // 110
	OP_3DUP                = 0x6f // 111
	OP_2OVER               = 0x70 // 112
	OP_2ROT                = 0x71 // 113
	OP_2SWAP               = 0x72 // 114
	OP_IFDUP               = 0x73 // 115
	OP_DEPTH               = 0x74 // 116
	OP_DROP                = 0x75 // 117
	OP_DUP                 = 0x76 // 118
	OP_NIP                 = 0x77 // 119
	OP_OVER                = 0x78 // 120
	OP_PICK                = 0x79 // 121
	OP_ROLL                = 0x7a // 122
	OP_ROT                 = 0x7b // 123
	OP_SWAP                = 0x7c // 124
	OP_TUCK                = 0x7d // 125
	OP_CAT                 = 0x7e // 126
	OP_SUBSTR              = 0x7f // 127
	OP_LEFT                = 0x80 // 128
	OP_RIGHT               = 0x81 // 129
	OP_SIZE                = 0x82 // 130
	OP_INVERT              = 0x83 // 131
	OP_AND                 = 0x84 // 132
	OP_OR                  = 0x85 // 133
	OP_XOR                 = 0x86 // 134
	OP_EQUAL               = 0x87 // 135
	OP_EQUALVERIFY         = 0x88 // 136
	OP_RESERVED1           = 0x89 // 137
	OP_RESERVED2           = 0x8a // 138
	OP_1ADD                = 0x8b // 139
	OP_1SUB                = 0x8c // 140
	OP_2MUL                = 0x8d // 141
	OP_2DIV                = 0x8e // 142
	OP_NEGATE              = 0x8f // 143
	OP_ABS                 = 0x90 // 144
	OP_NOT                 = 0x91 // 145
	OP_0NOTEQUAL           = 0x92 // 146
	OP_ADD                 = 0x93 // 147
	OP_SUB                 = 0x94 // 148
	OP_MUL                 = 0x95 // 149
	OP_DIV                 = 0x96 // 150
	OP_MOD                 = 0x97 // 151
	OP_LSHIFT              = 0x98 // 152
	OP_RSHIFT              = 0x99 // 153
	OP_BOOLAND             = 0x9a // 154
	OP_BOOLOR              = 0x9b // 155
	OP_NUMEQUAL            = 0x9c // 156
	OP_NUMEQUALVERIFY      = 0x9d // 157
	OP_NUMNOTEQUAL         = 0x9e // 158
	OP_LESSTHAN            = 0x9f // 159
	OP_GREATERTHAN         = 0xa0 // 160
	OP_LESSTHANOREQUAL     = 0xa1 // 161
	OP_GREATERTHANOREQUAL  = 0xa2 // 162
	OP_MIN                 = 0xa3 // 163
	OP_MAX                 = 0xa4 // 164
	OP_WITHIN              = 0xa5 // 165
	OP_RIPEMD160           = 0xa6 // 166
	OP_SHA1                = 0xa7 // 167
	OP_SHA256              = 0xa8 // 168
	OP_HASH160             = 0xa9 // 169
	OP_HASH256             = 0xaa // 170
	OP_CODESEPARATOR       = 0xab // 171
	OP_CHECKSIG            = 0xac // 172
	OP_CHECKSIGVERIFY      = 0xad // 173
	OP_CHECKMULTISIG       = 0xae // 174
	OP_CHECKMULTISIGVERIFY = 0xaf // 175
	OP_NOP1                = 0xb0 // 176
	OP_NOP2                = 0xb1 // 177
	OP_CHECKLOCKTIMEVERIFY = 0xb1 // 177 - AKA OP_NOP2
	OP_NOP3                = 0xb2 // 178
	OP_CHECKSEQUENCEVERIFY = 0xb2 // 178 - AKA OP_NOP3
	OP_NOP4                = 0xb3 // 179
	OP_NOP5                = 0xb4 // 180
	OP_NOP6                = 0xb5 // 181
	OP_NOP7                = 0xb6 // 182
	OP_NOP8                = 0xb7 // 183
	OP_NOP9                = 0xb8 // 184
	OP_NOP10               = 0xb9 // 185
	OP_CHECKSIGADD         = 0xba // 186
	OP_UNKNOWN187          = 0xbb // 187
	OP_UNKNOWN188          = 0xbc // 188
	OP_UNKNOWN189          = 0xbd // 189
	OP_UNKNOWN190          = 0xbe // 190
	OP_UNKNOWN191          = 0xbf // 191
	OP_UNKNOWN192          = 0xc0 // 192
	OP_UNKNOWN193          = 0xc1 // 193
	OP_UNKNOWN194          = 0xc2 // 194
	OP_UNKNOWN195          = 0xc3 // 195
	OP_SHA256INITIALIZE    = 0xc4 // 196
	OP_SHA256UPDATE        = 0xc5 // 197
	OP_SHA256FINALIZE      = 0xc6 // 198

	// Inputs
	OP_INSPECTINPUTOUTPOINT = 0xc7 // 199

	OP_UNKNOWN200 = 0xc8 // 200

	OP_INSPECTINPUTVALUE        = 0xc9 // 201
	OP_INSPECTINPUTSCRIPTPUBKEY = 0xca // 202
	OP_INSPECTINPUTSEQUENCE     = 0xcb // 203

	OP_CHECKSIGFROMSTACK = 0xcc // 204

	// current index
	OP_PUSHCURRENTINPUTINDEX = 0xcd // 205

	OP_UNKNOWN206 = 0xce // 206

	// outputs
	OP_INSPECTOUTPUTVALUE = 0xcf // 207

	OP_UNKNOWN208 = 0xd0 // 208

	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1 // 209

	// transaction
	OP_INSPECTVERSION    = 0xd2 // 210
	OP_INSPECTLOCKTIME   = 0xd3 // 211
	OP_INSPECTNUMINPUTS  = 0xd4 // 212
	OP_INSPECTNUMOUTPUTS = 0xd5 // 213
	OP_TXWEIGHT          = 0xd6 // 214

	OP_ADD64                = 0xd7
	OP_SUB64                = 0xd8
	OP_MUL64                = 0xd9
	OP_DIV64                = 0xda
	OP_NEG64                = 0xdb
	OP_LESSTHAN64           = 0xdc
	OP_LESSTHANOREQUAL64    = 0xdd
	OP_GREATERTHAN64        = 0xde
	OP_GREATERTHANOREQUAL64 = 0xdf // 223
	OP_SCRIPTNUMTOLE64      = 0xe0 // 224
	OP_LE64TOSCRIPTNUM      = 0xe1 // 225
	OP_LE32TOLE64           = 0xe2 // 226
	OP_ECMULSCALARVERIFY    = 0xe3 // 227
	OP_TWEAKVERIFY          = 0xe4 // 228
	OP_UNKNOWN229           = 0xe5 // 229
	OP_UNKNOWN230           = 0xe6 // 230
	OP_UNKNOWN231           = 0xe7 // 231
	OP_UNKNOWN232           = 0xe8 // 232
	OP_UNKNOWN233           = 0xe9 // 233
	OP_UNKNOWN234           = 0xea // 234
	OP_UNKNOWN235           = 0xeb // 235
	OP_UNKNOWN236           = 0xec // 236
	OP_UNKNOWN237           = 0xed // 237
	OP_UNKNOWN238           = 0xee // 238
	OP_UNKNOWN239           = 0xef // 239
	OP_UNKNOWN240           = 0xf0 // 240
	OP_UNKNOWN241           = 0xf1 // 241
	OP_UNKNOWN242           = 0xf2 // 242
	OP_UNKNOWN243           = 0xf3 // 243
	OP_UNKNOWN244           = 0xf4 // 244
	OP_UNKNOWN245           = 0xf5 // 245
	OP_UNKNOWN246           = 0xf6 // 246
	OP_UNKNOWN247           = 0xf7 // 247
	OP_UNKNOWN248           = 0xf8 // 248
	OP_UNKNOWN249           = 0xf9 // 249
	OP_SMALLINTEGER         = 0xfa // 250 - bitcoin core internal
	OP_PUBKEYS              = 0xfb // 251 - bitcoin core internal
	OP_UNKNOWN252           = 0xfc // 252
	OP_PUBKEYHASH           = 0xfd // 253 - bitcoin core internal
	OP_PUBKEY               = 0xfe // 254 - bitcoin core internal
	OP_INVALIDOPCODE        = 0xff // 255 - bitcoin core internal
)

// Conditional execution constants.
const (
	OpCondFalse = 0
	OpCondTrue  = 1
	OpCondSkip  = 2
)

// opcodeArray holds details about all possible opcodes such as how many bytes
// the opcode and any associated data should take, its human-readable name, and
// the handler function.
var opcodeArray = [256]opcode{
	// Data push opcodes.
	OP_FALSE:     {OP_FALSE, "OP_0", 1, opcodeFalse},
	OP_DATA_1:    {OP_DATA_1, "OP_DATA_1", 2, opcodePushData},
	OP_DATA_2:    {OP_DATA_2, "OP_DATA_2", 3, opcodePushData},
	OP_DATA_3:    {OP_DATA_3, "OP_DATA_3", 4, opcodePushData},
	OP_DATA_4:    {OP_DATA_4, "OP_DATA_4", 5, opcodePushData},
	OP_DATA_5:    {OP_DATA_5, "OP_DATA_5", 6, opcodePushData},
	OP_DATA_6:    {OP_DATA_6, "OP_DATA_6", 7, opcodePushData},
	OP_DATA_7:    {OP_DATA_7, "OP_DATA_7", 8, opcodePushData},
	OP_DATA_8:    {OP_DATA_8, "OP_DATA_8", 9, opcodePushData},
	OP_DATA_9:    {OP_DATA_9, "OP_DATA_9", 10, opcodePushData},
	OP_DATA_10:   {OP_DATA_10, "OP_DATA_10", 11, opcodePushData},
	OP_DATA_11:   {OP_DATA_11, "OP_DATA_11", 12, opcodePushData},
	OP_DATA_12:   {OP_DATA_12, "OP_DATA_12", 13, opcodePushData},
	OP_DATA_13:   {OP_DATA_13, "OP_DATA_13", 14, opcodePushData},
	OP_DATA_14:   {OP_DATA_14, "OP_DATA_14", 15, opcodePushData},
	OP_DATA_15:   {OP_DATA_15, "OP_DATA_15", 16, opcodePushData},
	OP_DATA_16:   {OP_DATA_16, "OP_DATA_16", 17, opcodePushData},
	OP_DATA_17:   {OP_DATA_17, "OP_DATA_17", 18, opcodePushData},
	OP_DATA_18:   {OP_DATA_18, "OP_DATA_18", 19, opcodePushData},
	OP_DATA_19:   {OP_DATA_19, "OP_DATA_19", 20, opcodePushData},
	OP_DATA_20:   {OP_DATA_20, "OP_DATA_20", 21, opcodePushData},
	OP_DATA_21:   {OP_DATA_21, "OP_DATA_21", 22, opcodePushData},
	OP_DATA_22:   {OP_DATA_22, "OP_DATA_22", 23, opcodePushData},
	OP_DATA_23:   {OP_DATA_23, "OP_DATA_23", 24, opcodePushData},
	OP_DATA_24:   {OP_DATA_24, "OP_DATA_24", 25, opcodePushData},
	OP_DATA_25:   {OP_DATA_25, "OP_DATA_25", 26, opcodePushData},
	OP_DATA_26:   {OP_DATA_26, "OP_DATA_26", 27, opcodePushData},
	OP_DATA_27:   {OP_DATA_27, "OP_DATA_27", 28, opcodePushData},
	OP_DATA_28:   {OP_DATA_28, "OP_DATA_28", 29, opcodePushData},
	OP_DATA_29:   {OP_DATA_29, "OP_DATA_29", 30, opcodePushData},
	OP_DATA_30:   {OP_DATA_30, "OP_DATA_30", 31, opcodePushData},
	OP_DATA_31:   {OP_DATA_31, "OP_DATA_31", 32, opcodePushData},
	OP_DATA_32:   {OP_DATA_32, "OP_DATA_32", 33, opcodePushData},
	OP_DATA_33:   {OP_DATA_33, "OP_DATA_33", 34, opcodePushData},
	OP_DATA_34:   {OP_DATA_34, "OP_DATA_34", 35, opcodePushData},
	OP_DATA_35:   {OP_DATA_35, "OP_DATA_35", 36, opcodePushData},
	OP_DATA_36:   {OP_DATA_36, "OP_DATA_36", 37, opcodePushData},
	OP_DATA_37:   {OP_DATA_37, "OP_DATA_37", 38, opcodePushData},
	OP_DATA_38:   {OP_DATA_38, "OP_DATA_38", 39, opcodePushData},
	OP_DATA_39:   {OP_DATA_39, "OP_DATA_39", 40, opcodePushData},
	OP_DATA_40:   {OP_DATA_40, "OP_DATA_40", 41, opcodePushData},
	OP_DATA_41:   {OP_DATA_41, "OP_DATA_41", 42, opcodePushData},
	OP_DATA_42:   {OP_DATA_42, "OP_DATA_42", 43, opcodePushData},
	OP_DATA_43:   {OP_DATA_43, "OP_DATA_43", 44, opcodePushData},
	OP_DATA_44:   {OP_DATA_44, "OP_DATA_44", 45, opcodePushData},
	OP_DATA_45:   {OP_DATA_45, "OP_DATA_45", 46, opcodePushData},
	OP_DATA_46:   {OP_DATA_46, "OP_DATA_46", 47, opcodePushData},
	OP_DATA_47:   {OP_DATA_47, "OP_DATA_47", 48, opcodePushData},
	OP_DATA_48:   {OP_DATA_48, "OP_DATA_48", 49, opcodePushData},
	OP_DATA_49:   {OP_DATA_49, "OP_DATA_49", 50, opcodePushData},
	OP_DATA_50:   {OP_DATA_50, "OP_DATA_50", 51, opcodePushData},
	OP_DATA_51:   {OP_DATA_51, "OP_DATA_51", 52, opcodePushData},
	OP_DATA_52:   {OP_DATA_52, "OP_DATA_52", 53, opcodePushData},
	OP_DATA_53:   {OP_DATA_53, "OP_DATA_53", 54, opcodePushData},
	OP_DATA_54:   {OP_DATA_54, "OP_DATA_54", 55, opcodePushData},
	OP_DATA_55:   {OP_DATA_55, "OP_DATA_55", 56, opcodePushData},
	OP_DATA_56:   {OP_DATA_56, "OP_DATA_56", 57, opcodePushData},
	OP_DATA_57:   {OP_DATA_57, "OP_DATA_57", 58, opcodePushData},
	OP_DATA_58:   {OP_DATA_58, "OP_DATA_58", 59, opcodePushData},
	OP_DATA_59:   {OP_DATA_59, "OP_DATA_59", 60, opcodePushData},
	OP_DATA_60:   {OP_DATA_60, "OP_DATA_60", 61, opcodePushData},
	OP_DATA_61:   {OP_DATA_61, "OP_DATA_61", 62, opcodePushData},
	OP_DATA_62:   {OP_DATA_62, "OP_DATA_62", 63, opcodePushData},
	OP_DATA_63:   {OP_DATA_63, "OP_DATA_63", 64, opcodePushData},
	OP_DATA_64:   {OP_DATA_64, "OP_DATA_64", 65, opcodePushData},
	OP_DATA_65:   {OP_DATA_65, "OP_DATA_65", 66, opcodePushData},
	OP_DATA_66:   {OP_DATA_66, "OP_DATA_66", 67, opcodePushData},
	OP_DATA_67:   {OP_DATA_67, "OP_DATA_67", 68, opcodePushData},
	OP_DATA_68:   {OP_DATA_68, "OP_DATA_68", 69, opcodePushData},
	OP_DATA_69:   {OP_DATA_69, "OP_DATA_69", 70, opcodePushData},
	OP_DATA_70:   {OP_DATA_70, "OP_DATA_70", 71, opcodePushData},
	OP_DATA_71:   {OP_DATA_71, "OP_DATA_71", 72, opcodePushData},
	OP_DATA_72:   {OP_DATA_72, "OP_DATA_72", 73, opcodePushData},
	OP_DATA_73:   {OP_DATA_73, "OP_DATA_73", 74, opcodePushData},
	OP_DATA_74:   {OP_DATA_74, "OP_DATA_74", 75, opcodePushData},
	OP_DATA_75:   {OP_DATA_75, "OP_DATA_75", 76, opcodePushData},
	OP_PUSHDATA1: {OP_PUSHDATA1, "OP_PUSHDATA1", -1, opcodePushData},
	OP_PUSHDATA2: {OP_PUSHDATA2, "OP_PUSHDATA2", -2, opcodePushData},
	OP_PUSHDATA4: {OP_PUSHDATA4, "OP_PUSHDATA4", -4, opcodePushData},
	OP_1NEGATE:   {OP_1NEGATE, "OP_1NEGATE", 1, opcode1Negate},
	OP_RESERVED:  {OP_RESERVED, "OP_RESERVED", 1, opcodeReserved},
	OP_TRUE:      {OP_TRUE, "OP_1", 1, opcodeN},
	OP_2:         {OP_2, "OP_2", 1, opcodeN},
	OP_3:         {OP_3, "OP_3", 1, opcodeN},
	OP_4:         {OP_4, "OP_4", 1, opcodeN},
	OP_5:         {OP_5, "OP_5", 1, opcodeN},
	OP_6:         {OP_6, "OP_6", 1, opcodeN},
	OP_7:         {OP_7, "OP_7", 1, opcodeN},
	OP_8:         {OP_8, "OP_8", 1, opcodeN},
	OP_9:         {OP_9, "OP_9", 1, opcodeN},
	OP_10:        {OP_10, "OP_10", 1, opcodeN},
	OP_11:        {OP_11, "OP_11", 1, opcodeN},
	OP_12:        {OP_12, "OP_12", 1, opcodeN},
	OP_13:        {OP_13, "OP_13", 1, opcodeN},
	OP_14:        {OP_14, "OP_14", 1, opcodeN},
	OP_15:        {OP_15, "OP_15", 1, opcodeN},
	OP_16:        {OP_16, "OP_16", 1, opcodeN},

	// Control opcodes.
	OP_NOP:                 {OP_NOP, "OP_NOP", 1, opcodeNop},
	OP_VER:                 {OP_VER, "OP_VER", 1, opcodeReserved},
	OP_IF:                  {OP_IF, "OP_IF", 1, opcodeIf},
	OP_NOTIF:               {OP_NOTIF, "OP_NOTIF", 1, opcodeNotIf},
	OP_VERIF:               {OP_VERIF, "OP_VERIF", 1, opcodeReserved},
	OP_VERNOTIF:            {OP_VERNOTIF, "OP_VERNOTIF", 1, opcodeReserved},
	OP_ELSE:                {OP_ELSE, "OP_ELSE", 1, opcodeElse},
	OP_ENDIF:               {OP_ENDIF, "OP_ENDIF", 1, opcodeEndif},
	OP_VERIFY:              {OP_VERIFY, "OP_VERIFY", 1, opcodeVerify},
	OP_RETURN:              {OP_RETURN, "OP_RETURN", 1, opcodeReturn},
	OP_CHECKLOCKTIMEVERIFY: {OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY", 1, opcodeCheckLockTimeVerify},
	OP_CHECKSEQUENCEVERIFY: {OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY", 1, opcodeCheckSequenceVerify},

	// Stack opcodes.
	OP_TOALTSTACK:   {OP_TOALTSTACK, "OP_TOALTSTACK", 1, opcodeToAltStack},
	OP_FROMALTSTACK: {OP_FROMALTSTACK, "OP_FROMALTSTACK", 1, opcodeFromAltStack},
	OP_2DROP:        {OP_2DROP, "OP_2DROP", 1, opcode2Drop},
	OP_2DUP:         {OP_2DUP, "OP_2DUP", 1, opcode2Dup},
	OP_3DUP:         {OP_3DUP, "OP_3DUP", 1, opcode3Dup},
	OP_2OVER:        {OP_2OVER, "OP_2OVER", 1, opcode2Over},
	OP_2ROT:         {OP_2ROT, "OP_2ROT", 1, opcode2Rot},
	OP_2SWAP:        {OP_2SWAP, "OP_2SWAP", 1, opcode2Swap},
	OP_IFDUP:        {OP_IFDUP, "OP_IFDUP", 1, opcodeIfDup},
	OP_DEPTH:        {OP_DEPTH, "OP_DEPTH", 1, opcodeDepth},
	OP_DROP:         {OP_DROP, "OP_DROP", 1, opcodeDrop},
	OP_DUP:          {OP_DUP, "OP_DUP", 1, opcodeDup},
	OP_NIP:          {OP_NIP, "OP_NIP", 1, opcodeNip},
	OP_OVER:         {OP_OVER, "OP_OVER", 1, opcodeOver},
	OP_PICK:         {OP_PICK, "OP_PICK", 1, opcodePick},
	OP_ROLL:         {OP_ROLL, "OP_ROLL", 1, opcodeRoll},
	OP_ROT:          {OP_ROT, "OP_ROT", 1, opcodeRot},
	OP_SWAP:         {OP_SWAP, "OP_SWAP", 1, opcodeSwap},
	OP_TUCK:         {OP_TUCK, "OP_TUCK", 1, opcodeTuck},

	// Splice opcodes.
	OP_CAT:    {OP_CAT, "OP_CAT", 1, opcodeCat},
	OP_SUBSTR: {OP_SUBSTR, "OP_SUBSTR", 1, opcodeSubstr},
	OP_LEFT:   {OP_LEFT, "OP_LEFT", 1, opcodeLeft},
	OP_RIGHT:  {OP_RIGHT, "OP_RIGHT", 1, opcodeRight},
	OP_SIZE:   {OP_SIZE, "OP_SIZE", 1, opcodeSize},

	// Bitwise logic opcodes.
	OP_INVERT:      {OP_INVERT, "OP_INVERT", 1, opcodeInvert},
	OP_AND:         {OP_AND, "OP_AND", 1, opcodeAnd},
	OP_OR:          {OP_OR, "OP_OR", 1, opcodeOr},
	OP_XOR:         {OP_XOR, "OP_XOR", 1, opcodeXor},
	OP_EQUAL:       {OP_EQUAL, "OP_EQUAL", 1, opcodeEqual},
	OP_EQUALVERIFY: {OP_EQUALVERIFY, "OP_EQUALVERIFY", 1, opcodeEqualVerify},
	OP_RESERVED1:   {OP_RESERVED1, "OP_RESERVED1", 1, opcodeReserved},
	OP_RESERVED2:   {OP_RESERVED2, "OP_RESERVED2", 1, opcodeReserved},

	// Numeric related opcodes.
	OP_1ADD:               {OP_1ADD, "OP_1ADD", 1, opcode1Add},
	OP_1SUB:               {OP_1SUB, "OP_1SUB", 1, opcode1Sub},
	OP_2MUL:               {OP_2MUL, "OP_2MUL", 1, opcode2Mul},
	OP_2DIV:               {OP_2DIV, "OP_2DIV", 1, opcode2Div},
	OP_NEGATE:             {OP_NEGATE, "OP_NEGATE", 1, opcodeNegate},
	OP_ABS:                {OP_ABS, "OP_ABS", 1, opcodeAbs},
	OP_NOT:                {OP_NOT, "OP_NOT", 1, opcodeNot},
	OP_0NOTEQUAL:          {OP_0NOTEQUAL, "OP_0NOTEQUAL", 1, opcode0NotEqual},
	OP_ADD:                {OP_ADD, "OP_ADD", 1, opcodeAdd},
	OP_SUB:                {OP_SUB, "OP_SUB", 1, opcodeSub},
	OP_MUL:                {OP_MUL, "OP_MUL", 1, opcodeMul},
	OP_DIV:                {OP_DIV, "OP_DIV", 1, opcodeDiv},
	OP_MOD:                {OP_MOD, "OP_MOD", 1, opcodeMod},
	OP_LSHIFT:             {OP_LSHIFT, "OP_LSHIFT", 1, opcodeLshift},
	OP_RSHIFT:             {OP_RSHIFT, "OP_RSHIFT", 1, opcodeRshift},
	OP_BOOLAND:            {OP_BOOLAND, "OP_BOOLAND", 1, opcodeBoolAnd},
	OP_BOOLOR:             {OP_BOOLOR, "OP_BOOLOR", 1, opcodeBoolOr},
	OP_NUMEQUAL:           {OP_NUMEQUAL, "OP_NUMEQUAL", 1, opcodeNumEqual},
	OP_NUMEQUALVERIFY:     {OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY", 1, opcodeNumEqualVerify},
	OP_NUMNOTEQUAL:        {OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL", 1, opcodeNumNotEqual},
	OP_LESSTHAN:           {OP_LESSTHAN, "OP_LESSTHAN", 1, opcodeLessThan},
	OP_GREATERTHAN:        {OP_GREATERTHAN, "OP_GREATERTHAN", 1, opcodeGreaterThan},
	OP_LESSTHANOREQUAL:    {OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL", 1, opcodeLessThanOrEqual},
	OP_GREATERTHANOREQUAL: {OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL", 1, opcodeGreaterThanOrEqual},
	OP_MIN:                {OP_MIN, "OP_MIN", 1, opcodeMin},
	OP_MAX:                {OP_MAX, "OP_MAX", 1, opcodeMax},
	OP_WITHIN:             {OP_WITHIN, "OP_WITHIN", 1, opcodeWithin},

	// Crypto opcodes.
	OP_RIPEMD160:           {OP_RIPEMD160, "OP_RIPEMD160", 1, opcodeRipemd160},
	OP_SHA1:                {OP_SHA1, "OP_SHA1", 1, opcodeSha1},
	OP_SHA256:              {OP_SHA256, "OP_SHA256", 1, opcodeSha256},
	OP_HASH160:             {OP_HASH160, "OP_HASH160", 1, opcodeHash160},
	OP_HASH256:             {OP_HASH256, "OP_HASH256", 1, opcodeHash256},
	OP_CODESEPARATOR:       {OP_CODESEPARATOR, "OP_CODESEPARATOR", 1, opcodeCodeSeparator},
	OP_CHECKSIG:            {OP_CHECKSIG, "OP_CHECKSIG", 1, opcodeCheckSig},
	OP_CHECKSIGVERIFY:      {OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY", 1, opcodeCheckSigVerify},
	OP_CHECKMULTISIG:       {OP_CHECKMULTISIG, "OP_CHECKMULTISIG", 1, opcodeCheckMultiSig},
	OP_CHECKMULTISIGVERIFY: {OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY", 1, opcodeCheckMultiSigVerify},
	OP_CHECKSIGADD:         {OP_CHECKSIGADD, "OP_CHECKSIGADD", 1, opcodeCheckSigAdd},

	// Reserved opcodes.
	OP_NOP1:  {OP_NOP1, "OP_NOP1", 1, opcodeNop},
	OP_NOP4:  {OP_NOP4, "OP_NOP4", 1, opcodeNop},
	OP_NOP5:  {OP_NOP5, "OP_NOP5", 1, opcodeNop},
	OP_NOP6:  {OP_NOP6, "OP_NOP6", 1, opcodeNop},
	OP_NOP7:  {OP_NOP7, "OP_NOP7", 1, opcodeNop},
	OP_NOP8:  {OP_NOP8, "OP_NOP8", 1, opcodeNop},
	OP_NOP9:  {OP_NOP9, "OP_NOP9", 1, opcodeNop},
	OP_NOP10: {OP_NOP10, "OP_NOP10", 1, opcodeNop},

	// Undefined opcodes.
	OP_UNKNOWN187: {OP_UNKNOWN187, "OP_UNKNOWN187", 1, opcodeInvalid},
	OP_UNKNOWN188: {OP_UNKNOWN188, "OP_UNKNOWN188", 1, opcodeInvalid},
	OP_UNKNOWN189: {OP_UNKNOWN189, "OP_UNKNOWN189", 1, opcodeInvalid},
	OP_UNKNOWN190: {OP_UNKNOWN190, "OP_UNKNOWN190", 1, opcodeInvalid},
	OP_UNKNOWN191: {OP_UNKNOWN191, "OP_UNKNOWN191", 1, opcodeInvalid},
	OP_UNKNOWN192: {OP_UNKNOWN192, "OP_UNKNOWN192", 1, opcodeInvalid},
	OP_UNKNOWN193: {OP_UNKNOWN193, "OP_UNKNOWN193", 1, opcodeInvalid},
	OP_UNKNOWN194: {OP_UNKNOWN194, "OP_UNKNOWN194", 1, opcodeInvalid},
	OP_UNKNOWN195: {OP_UNKNOWN195, "OP_UNKNOWN195", 1, opcodeInvalid},
	// Streaming opcodes
	OP_SHA256INITIALIZE: {OP_SHA256INITIALIZE, "OP_SHA256INITIALIZE", 1, opcodeSha256Initialize},
	OP_SHA256UPDATE:     {OP_SHA256UPDATE, "OP_SHA256UPDATE", 1, opcodeSha256Update},
	OP_SHA256FINALIZE:   {OP_SHA256FINALIZE, "OP_SHA256FINALIZE", 1, opcodeSha256Finalize},

	// Inputs introspection
	OP_INSPECTINPUTOUTPOINT: {OP_INSPECTINPUTOUTPOINT, "OP_INSPECTINPUTOUTPOINT", 1, opcodeInspectInputOutpoint},

	OP_UNKNOWN200: {OP_UNKNOWN200, "OP_UNKNOWN200", 1, opcodeInvalid},

	OP_INSPECTINPUTVALUE:        {OP_INSPECTINPUTVALUE, "OP_INSPECTINPUTVALUE", 1, opcodeInspectInputValue},
	OP_INSPECTINPUTSCRIPTPUBKEY: {OP_INSPECTINPUTSCRIPTPUBKEY, "OP_INSPECTINPUTSCRIPTPUBKEY", 1, opcodeInspectInputScriptPubkey},
	OP_INSPECTINPUTSEQUENCE:     {OP_INSPECTINPUTSEQUENCE, "OP_INSPECTINPUTSEQUENCE", 1, opcodeInspectInputSequence},

	OP_CHECKSIGFROMSTACK: {OP_CHECKSIGFROMSTACK, "OP_CHECKSIGFROMSTACK", 1, opcodeChecksigFromStack},

	OP_PUSHCURRENTINPUTINDEX: {OP_PUSHCURRENTINPUTINDEX, "OP_PUSHCURRENTINPUTINDEX", 1, opcodePushCurrentInputIndex},

	// Outputs introspection
	OP_UNKNOWN206: {OP_UNKNOWN206, "OP_UNKNOWN206", 1, opcodeInvalid},

	OP_INSPECTOUTPUTVALUE: {OP_INSPECTOUTPUTVALUE, "OP_INSPECTOUTPUTVALUE", 1, opcodeInspectOutputValue},

	OP_UNKNOWN208: {OP_UNKNOWN208, "OP_UNKNOWN208", 1, opcodeInvalid},

	OP_INSPECTOUTPUTSCRIPTPUBKEY: {OP_INSPECTOUTPUTSCRIPTPUBKEY, "OP_INSPECTOUTPUTSCRIPTPUBKEY", 1, opcodeInspectOutputScriptPubkey},

	// Transaction introspection
	OP_INSPECTVERSION:    {OP_INSPECTVERSION, "OP_INSPECTVERSION", 1, opcodeInspectVersion},
	OP_INSPECTLOCKTIME:   {OP_INSPECTLOCKTIME, "OP_INSPECTLOCKTIME", 1, opcodeInspectLocktime},
	OP_INSPECTNUMINPUTS:  {OP_INSPECTNUMINPUTS, "OP_INSPECTNUMINPUTS", 1, opcodeInspectNumInputs},
	OP_INSPECTNUMOUTPUTS: {OP_INSPECTNUMOUTPUTS, "OP_INSPECTNUMOUTPUTS", 1, opcodeInspectNumOutputs},
	OP_TXWEIGHT:          {OP_TXWEIGHT, "OP_TXWEIGHT", 1, opcodeTxWeight},

	OP_ADD64:                {OP_ADD64, "OP_ADD64", 1, opcodeAdd64},
	OP_SUB64:                {OP_SUB64, "OP_SUB64", 1, opcodeSub64},
	OP_MUL64:                {OP_MUL64, "OP_MUL64", 1, opcodeMul64},
	OP_DIV64:                {OP_DIV64, "OP_DIV64", 1, opcodeDiv64},
	OP_NEG64:                {OP_NEG64, "OP_NEG64", 1, opcodeNeg64},
	OP_LESSTHAN64:           {OP_LESSTHAN64, "OP_LESSTHAN64", 1, opcodeLessThan64},
	OP_LESSTHANOREQUAL64:    {OP_LESSTHANOREQUAL64, "OP_LESSTHANOREQUAL64", 1, opcodeLessThanOrEqual64},
	OP_GREATERTHAN64:        {OP_GREATERTHAN64, "OP_GREATERTHAN64", 1, opcodeGreaterThan64},
	OP_GREATERTHANOREQUAL64: {OP_GREATERTHANOREQUAL64, "OP_GREATERTHANOREQUAL64", 1, opcodeGreaterThanOrEqual64},
	OP_SCRIPTNUMTOLE64:      {OP_SCRIPTNUMTOLE64, "OP_SCRIPTNUMTOLE64", 1, opcodeScriptNumToLE64},
	OP_LE64TOSCRIPTNUM:      {OP_LE64TOSCRIPTNUM, "OP_LE64TOSCRIPTNUM", 1, opcodeLE64ToScriptNum},
	OP_LE32TOLE64:           {OP_LE32TOLE64, "OP_LE32TOLE64", 1, opcodeLE32ToLE64},
	OP_ECMULSCALARVERIFY:    {OP_ECMULSCALARVERIFY, "OP_ECMULSCALARVERIFY", 1, opcodeECMulScalarVerify},
	OP_TWEAKVERIFY:          {OP_TWEAKVERIFY, "OP_TWEAKVERIFY", 1, opcodeTweakVerify},
	OP_UNKNOWN229:           {OP_UNKNOWN229, "OP_UNKNOWN229", 1, opcodeInvalid},
	OP_UNKNOWN230:           {OP_UNKNOWN230, "OP_UNKNOWN230", 1, opcodeInvalid},
	OP_UNKNOWN231:           {OP_UNKNOWN231, "OP_UNKNOWN231", 1, opcodeInvalid},
	OP_UNKNOWN232:           {OP_UNKNOWN232, "OP_UNKNOWN232", 1, opcodeInvalid},
	OP_UNKNOWN233:           {OP_UNKNOWN233, "OP_UNKNOWN233", 1, opcodeInvalid},
	OP_UNKNOWN234:           {OP_UNKNOWN234, "OP_UNKNOWN234", 1, opcodeInvalid},
	OP_UNKNOWN235:           {OP_UNKNOWN235, "OP_UNKNOWN235", 1, opcodeInvalid},
	OP_UNKNOWN236:           {OP_UNKNOWN236, "OP_UNKNOWN236", 1, opcodeInvalid},
	OP_UNKNOWN237:           {OP_UNKNOWN237, "OP_UNKNOWN237", 1, opcodeInvalid},
	OP_UNKNOWN238:           {OP_UNKNOWN238, "OP_UNKNOWN238", 1, opcodeInvalid},
	OP_UNKNOWN239:           {OP_UNKNOWN239, "OP_UNKNOWN239", 1, opcodeInvalid},
	OP_UNKNOWN240:           {OP_UNKNOWN240, "OP_UNKNOWN240", 1, opcodeInvalid},
	OP_UNKNOWN241:           {OP_UNKNOWN241, "OP_UNKNOWN241", 1, opcodeInvalid},
	OP_UNKNOWN242:           {OP_UNKNOWN242, "OP_UNKNOWN242", 1, opcodeInvalid},
	OP_UNKNOWN243:           {OP_UNKNOWN243, "OP_UNKNOWN243", 1, opcodeInvalid},
	OP_UNKNOWN244:           {OP_UNKNOWN244, "OP_UNKNOWN244", 1, opcodeInvalid},
	OP_UNKNOWN245:           {OP_UNKNOWN245, "OP_UNKNOWN245", 1, opcodeInvalid},
	OP_UNKNOWN246:           {OP_UNKNOWN246, "OP_UNKNOWN246", 1, opcodeInvalid},
	OP_UNKNOWN247:           {OP_UNKNOWN247, "OP_UNKNOWN247", 1, opcodeInvalid},
	OP_UNKNOWN248:           {OP_UNKNOWN248, "OP_UNKNOWN248", 1, opcodeInvalid},
	OP_UNKNOWN249:           {OP_UNKNOWN249, "OP_UNKNOWN249", 1, opcodeInvalid},

	// Bitcoin Core internal use opcode.  Defined here for completeness.
	OP_SMALLINTEGER: {OP_SMALLINTEGER, "OP_SMALLINTEGER", 1, opcodeInvalid},
	OP_PUBKEYS:      {OP_PUBKEYS, "OP_PUBKEYS", 1, opcodeInvalid},
	OP_UNKNOWN252:   {OP_UNKNOWN252, "OP_UNKNOWN252", 1, opcodeInvalid},
	OP_PUBKEYHASH:   {OP_PUBKEYHASH, "OP_PUBKEYHASH", 1, opcodeInvalid},
	OP_PUBKEY:       {OP_PUBKEY, "OP_PUBKEY", 1, opcodeInvalid},

	OP_INVALIDOPCODE: {OP_INVALIDOPCODE, "OP_INVALIDOPCODE", 1, opcodeInvalid},
}

// opcodeOnelineRepls defines opcode names which are replaced when doing a
// one-line disassembly.  This is done to match the output of the reference
// implementation while not changing the opcode names in the nicer full
// disassembly.
var opcodeOnelineRepls = map[string]string{
	"OP_1NEGATE": "-1",
	"OP_0":       "0",
	"OP_1":       "1",
	"OP_2":       "2",
	"OP_3":       "3",
	"OP_4":       "4",
	"OP_5":       "5",
	"OP_6":       "6",
	"OP_7":       "7",
	"OP_8":       "8",
	"OP_9":       "9",
	"OP_10":      "10",
	"OP_11":      "11",
	"OP_12":      "12",
	"OP_13":      "13",
	"OP_14":      "14",
	"OP_15":      "15",
	"OP_16":      "16",
}

// disasmOpcode writes a human-readable disassembly of the provided opcode and
// data into the provided buffer.  The compact flag indicates the disassembly
// should print a more compact representation of data-carrying and small integer
// opcodes.  For example, OP_0 through OP_16 are replaced with the numeric value
// and data pushes are printed as only the hex representation of the data as
// opposed to including the opcode that specifies the amount of data to push as
// well.
func disasmOpcode(buf *strings.Builder, op *opcode, data []byte, compact bool) {
	// Replace opcode which represent values (e.g. OP_0 through OP_16 and
	// OP_1NEGATE) with the raw value when performing a compact disassembly.
	opcodeName := op.name
	if compact {
		if replName, ok := opcodeOnelineRepls[opcodeName]; ok {
			opcodeName = replName
		}

		// Either write the human-readable opcode or the parsed data in hex for
		// data-carrying opcodes.
		switch {
		case op.length == 1:
			buf.WriteString(opcodeName)

		default:
			buf.WriteString(hex.EncodeToString(data))
		}

		return
	}

	buf.WriteString(opcodeName)

	switch op.length {
	// Only write the opcode name for non-data push opcodes.
	case 1:
		return

	// Add length for the OP_PUSHDATA# opcodes.
	case -1:
		buf.WriteString(fmt.Sprintf(" 0x%02x", len(data)))
	case -2:
		buf.WriteString(fmt.Sprintf(" 0x%04x", len(data)))
	case -4:
		buf.WriteString(fmt.Sprintf(" 0x%08x", len(data)))
	}

	buf.WriteString(fmt.Sprintf(" 0x%02x", data))
}

// *******************************************
// Opcode implementation functions start here.
// *******************************************

// opcodeReserved is a common handler for all reserved opcodes.  It returns an
// appropriate error indicating the opcode is reserved.
func opcodeReserved(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute reserved opcode %s", op.name)
	return scriptError(txscript.ErrReservedOpcode, str)
}

// opcodeInvalid is a common handler for all invalid opcodes.  It returns an
// appropriate error indicating the opcode is invalid.
func opcodeInvalid(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute invalid opcode %s", op.name)
	return scriptError(txscript.ErrReservedOpcode, str)
}

// opcodeFalse pushes an empty array to the data stack to represent false.  Note
// that 0, when encoded as a number according to the numeric encoding consensus
// rules, is an empty array.
func opcodeFalse(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushByteArray(nil)
	return nil
}

// opcodePushData is a common handler for the vast majority of opcodes that push
// raw data (bytes) to the data stack.
func opcodePushData(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushByteArray(data)
	return nil
}

// opcode1Negate pushes -1, encoded as a number, to the data stack.
func opcode1Negate(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(-1))
	return nil
}

// opcodeN is a common handler for the small integer data push opcodes.  It
// pushes the numeric value the opcode represents (which will be from 1 to 16)
// onto the data stack.
func opcodeN(op *opcode, data []byte, vm *Engine) error {
	// The opcodes are all defined consecutively, so the numeric value is
	// the difference.
	vm.dstack.PushInt(scriptNum((op.value - (OP_1 - 1))))
	return nil
}

// opcodeNop is a common handler for the NOP family of opcodes.  As the name
// implies it generally does nothing, however, it will return an error when
// the flag to discourage use of NOPs is set for select opcodes.
func opcodeNop(op *opcode, data []byte, vm *Engine) error {
	switch op.value {
	case OP_NOP1, OP_NOP4, OP_NOP5,
		OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10:

		if vm.hasFlag(txscript.ScriptDiscourageUpgradableNops) {
			str := fmt.Sprintf("%v reserved for soft-fork "+
				"upgrades", op.name)
			return scriptError(txscript.ErrDiscourageUpgradableNOPs, str)
		}
	}
	return nil
}

// popIfBool enforces the "minimal if" policy during script execution if the
// particular flag is set.  If so, in order to eliminate an additional source
// of nuisance malleability, post-segwit for version 0 witness programs, we now
// require the following: for OP_IF and OP_NOT_IF, the top stack item MUST
// either be an empty byte slice, or [0x01]. Otherwise, the item at the top of
// the stack will be popped and interpreted as a boolean.
func popIfBool(vm *Engine) (bool, error) {
	// When not in witness execution mode, not executing a v0 witness
	// program, or not doing tapscript execution, or the minimal if flag
	// isn't set pop the top stack item as a normal bool.
	switch {
	// Minimal if is always on for taproot execution.
	case vm.isWitnessVersionActive(txscript.TaprootWitnessVersion):
		break

	// If this isn't the base segwit version, then we'll coerce the stack
	// element as a bool as normal.
	case !vm.isWitnessVersionActive(txscript.BaseSegwitWitnessVersion):
		fallthrough

	// If the minimal if flag isn't set, then we don't need any extra
	// checks here.
	case !vm.hasFlag(txscript.ScriptVerifyMinimalIf):
		return vm.dstack.PopBool()
	}

	// At this point, a v0 or v1 witness program is being executed and the
	// minimal if flag is set, so enforce additional constraints on the top
	// stack item.
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return false, err
	}

	// The top element MUST have a length of at least one.
	if len(so) > 1 {
		str := fmt.Sprintf("minimal if is active, top element MUST "+
			"have a length of at least, instead length is %v",
			len(so))
		return false, scriptError(txscript.ErrMinimalIf, str)
	}

	// Additionally, if the length is one, then the value MUST be 0x01.
	if len(so) == 1 && so[0] != 0x01 {
		str := fmt.Sprintf("minimal if is active, top stack item MUST "+
			"be an empty byte array or 0x01, is instead: %v",
			so[0])
		return false, scriptError(txscript.ErrMinimalIf, str)
	}

	return asBool(so), nil
}

// opcodeIf treats the top item on the data stack as a boolean and removes it.
//
// An appropriate entry is added to the conditional stack depending on whether
// the boolean is true and whether this if is on an executing branch in order
// to allow proper execution of further opcodes depending on the conditional
// logic.  When the boolean is true, the first branch will be executed (unless
// this opcode is nested in a non-executed branch).
//
// <expression> if [statements] [else [statements]] endif
//
// Note that, unlike for all non-conditional opcodes, this is executed even when
// it is on a non-executing branch so proper nesting is maintained.
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeIf(op *opcode, data []byte, vm *Engine) error {
	condVal := OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if ok {
			condVal = OpCondTrue
		}
	} else {
		condVal = OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeNotIf treats the top item on the data stack as a boolean and removes
// it.
//
// An appropriate entry is added to the conditional stack depending on whether
// the boolean is true and whether this if is on an executing branch in order
// to allow proper execution of further opcodes depending on the conditional
// logic.  When the boolean is false, the first branch will be executed (unless
// this opcode is nested in a non-executed branch).
//
// <expression> notif [statements] [else [statements]] endif
//
// Note that, unlike for all non-conditional opcodes, this is executed even when
// it is on a non-executing branch so proper nesting is maintained.
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeNotIf(op *opcode, data []byte, vm *Engine) error {
	condVal := OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if !ok {
			condVal = OpCondTrue
		}
	} else {
		condVal = OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeElse inverts conditional execution for other half of if/else/endif.
//
// An error is returned if there has not already been a matching OP_IF.
//
// Conditional stack transformation: [... OpCondValue] -> [... !OpCondValue]
func opcodeElse(op *opcode, data []byte, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.name)
		return scriptError(txscript.ErrUnbalancedConditional, str)
	}

	conditionalIdx := len(vm.condStack) - 1
	switch vm.condStack[conditionalIdx] {
	case OpCondTrue:
		vm.condStack[conditionalIdx] = OpCondFalse
	case OpCondFalse:
		vm.condStack[conditionalIdx] = OpCondTrue
	case OpCondSkip:
		// Value doesn't change in skip since it indicates this opcode
		// is nested in a non-executed branch.
	}
	return nil
}

// opcodeEndif terminates a conditional block, removing the value from the
// conditional execution stack.
//
// An error is returned if there has not already been a matching OP_IF.
//
// Conditional stack transformation: [... OpCondValue] -> [...]
func opcodeEndif(op *opcode, data []byte, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.name)
		return scriptError(txscript.ErrUnbalancedConditional, str)
	}

	vm.condStack = vm.condStack[:len(vm.condStack)-1]
	return nil
}

// abstractVerify examines the top item on the data stack as a boolean value and
// verifies it evaluates to true.  An error is returned either when there is no
// item on the stack or when that item evaluates to false.  In the latter case
// where the verification fails specifically due to the top item evaluating
// to false, the returned error will use the passed error code.
func abstractVerify(op *opcode, vm *Engine, c txscript.ErrorCode) error {
	verified, err := vm.dstack.PopBool()
	if err != nil {
		return err
	}

	if !verified {
		str := fmt.Sprintf("%s failed", op.name)
		return scriptError(c, str)
	}
	return nil
}

// opcodeVerify examines the top item on the data stack as a boolean value and
// verifies it evaluates to true.  An error is returned if it does not.
func opcodeVerify(op *opcode, data []byte, vm *Engine) error {
	return abstractVerify(op, vm, txscript.ErrVerify)
}

// opcodeReturn returns an appropriate error since it is always an error to
// return early from a script.
func opcodeReturn(op *opcode, data []byte, vm *Engine) error {
	return scriptError(txscript.ErrEarlyReturn, "script returned early")
}

// verifyLockTime is a helper function used to validate locktimes.
func verifyLockTime(txLockTime, threshold, lockTime int64) error {
	// The lockTimes in both the script and transaction must be of the same
	// type.
	if !((txLockTime < threshold && lockTime < threshold) ||
		(txLockTime >= threshold && lockTime >= threshold)) {
		str := fmt.Sprintf("mismatched locktime types -- tx locktime "+
			"%d, stack locktime %d", txLockTime, lockTime)
		return scriptError(txscript.ErrUnsatisfiedLockTime, str)
	}

	if lockTime > txLockTime {
		str := fmt.Sprintf("locktime requirement not satisfied -- "+
			"locktime is greater than the transaction locktime: "+
			"%d > %d", lockTime, txLockTime)
		return scriptError(txscript.ErrUnsatisfiedLockTime, str)
	}

	return nil
}

// opcodeCheckLockTimeVerify compares the top item on the data stack to the
// LockTime field of the transaction containing the script signature
// validating if the transaction outputs are spendable yet.  If flag
// ScriptVerifyCheckLockTimeVerify is not set, the code continues as if OP_NOP2
// were executed.
func opcodeCheckLockTimeVerify(op *opcode, data []byte, vm *Engine) error {
	// If the ScriptVerifyCheckLockTimeVerify script flag is not set, treat
	// opcode as OP_NOP2 instead.
	if !vm.hasFlag(txscript.ScriptVerifyCheckLockTimeVerify) {
		if vm.hasFlag(txscript.ScriptDiscourageUpgradableNops) {
			return scriptError(txscript.ErrDiscourageUpgradableNOPs,
				"OP_NOP2 reserved for soft-fork upgrades")
		}
		return nil
	}

	// The current transaction locktime is a uint32 resulting in a maximum
	// locktime of 2^32-1 (the year 2106).  However, scriptNums are signed
	// and therefore a standard 4-byte scriptNum would only support up to a
	// maximum of 2^31-1 (the year 2038).  Thus, a 5-byte scriptNum is used
	// here since it will support up to 2^39-1 which allows dates beyond the
	// current locktime limit.
	//
	// PeekByteArray is used here instead of PeekInt because we do not want
	// to be limited to a 4-byte integer for reasons specified above.
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}
	lockTime, err := MakeScriptNum(so, vm.dstack.verifyMinimalData, 5)
	if err != nil {
		return err
	}

	// In the rare event that the argument needs to be < 0 due to some
	// arithmetic being done first, you can always use
	// 0 OP_MAX OP_CHECKLOCKTIMEVERIFY.
	if lockTime < 0 {
		str := fmt.Sprintf("negative lock time: %d", lockTime)
		return scriptError(txscript.ErrNegativeLockTime, str)
	}

	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the txscript.LockTimeThreshold.  When it is under the
	// threshold it is a block height.
	err = verifyLockTime(int64(vm.tx.LockTime), txscript.LockTimeThreshold,
		int64(lockTime))
	if err != nil {
		return err
	}

	// The lock time feature can also be disabled, thereby bypassing
	// OP_CHECKLOCKTIMEVERIFY, if every transaction input has been finalized by
	// setting its sequence to the maximum value (wire.MaxTxInSequenceNum).  This
	// condition would result in the transaction being allowed into the blockchain
	// making the opcode ineffective.
	//
	// This condition is prevented by enforcing that the input being used by
	// the opcode is unlocked (its sequence number is less than the max
	// value).  This is sufficient to prove correctness without having to
	// check every input.
	//
	// NOTE: This implies that even if the transaction is not finalized due to
	// another input being unlocked, the opcode execution will still fail when the
	// input being used by the opcode is locked.
	if vm.tx.TxIn[vm.txIdx].Sequence == wire.MaxTxInSequenceNum {
		return scriptError(txscript.ErrUnsatisfiedLockTime,
			"transaction input is finalized")
	}

	return nil
}

// opcodeCheckSequenceVerify compares the top item on the data stack to the
// LockTime field of the transaction containing the script signature
// validating if the transaction outputs are spendable yet.  If flag
// ScriptVerifyCheckSequenceVerify is not set, the code continues as if OP_NOP3
// were executed.
func opcodeCheckSequenceVerify(op *opcode, data []byte, vm *Engine) error {
	// If the ScriptVerifyCheckSequenceVerify script flag is not set, treat
	// opcode as OP_NOP3 instead.
	if !vm.hasFlag(txscript.ScriptVerifyCheckSequenceVerify) {
		if vm.hasFlag(txscript.ScriptDiscourageUpgradableNops) {
			return scriptError(txscript.ErrDiscourageUpgradableNOPs,
				"OP_NOP3 reserved for soft-fork upgrades")
		}
		return nil
	}

	// The current transaction sequence is a uint32 resulting in a maximum
	// sequence of 2^32-1.  However, scriptNums are signed and therefore a
	// standard 4-byte scriptNum would only support up to a maximum of
	// 2^31-1.  Thus, a 5-byte scriptNum is used here since it will support
	// up to 2^39-1 which allows sequences beyond the current sequence
	// limit.
	//
	// PeekByteArray is used here instead of PeekInt because we do not want
	// to be limited to a 4-byte integer for reasons specified above.
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}
	stackSequence, err := MakeScriptNum(so, vm.dstack.verifyMinimalData, 5)
	if err != nil {
		return err
	}

	// In the rare event that the argument needs to be < 0 due to some
	// arithmetic being done first, you can always use
	// 0 OP_MAX OP_CHECKSEQUENCEVERIFY.
	if stackSequence < 0 {
		str := fmt.Sprintf("negative sequence: %d", stackSequence)
		return scriptError(txscript.ErrNegativeLockTime, str)
	}

	sequence := int64(stackSequence)

	// To provide for future soft-fork extensibility, if the
	// operand has the disabled lock-time flag set,
	// CHECKSEQUENCEVERIFY behaves as a NOP.
	if sequence&int64(wire.SequenceLockTimeDisabled) != 0 {
		return nil
	}

	// Transaction version numbers not high enough to trigger CSV rules must
	// fail.
	if uint32(vm.tx.Version) < 2 {
		str := fmt.Sprintf("invalid transaction version: %d",
			vm.tx.Version)
		return scriptError(txscript.ErrUnsatisfiedLockTime, str)
	}

	// Sequence numbers with their most significant bit set are not
	// consensus constrained. Testing that the transaction's sequence
	// number does not have this bit set prevents using this property
	// to get around a CHECKSEQUENCEVERIFY check.
	txSequence := int64(vm.tx.TxIn[vm.txIdx].Sequence)
	if txSequence&int64(wire.SequenceLockTimeDisabled) != 0 {
		str := fmt.Sprintf("transaction sequence has sequence "+
			"locktime disabled bit set: 0x%x", txSequence)
		return scriptError(txscript.ErrUnsatisfiedLockTime, str)
	}

	// Mask off non-consensus bits before doing comparisons.
	lockTimeMask := int64(wire.SequenceLockTimeIsSeconds |
		wire.SequenceLockTimeMask)
	return verifyLockTime(txSequence&lockTimeMask,
		wire.SequenceLockTimeIsSeconds, sequence&lockTimeMask)
}

// opcodeToAltStack removes the top item from the main data stack and pushes it
// onto the alternate data stack.
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2 y3 x3]
func opcodeToAltStack(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	vm.astack.PushByteArray(so)

	return nil
}

// opcodeFromAltStack removes the top item from the alternate data stack and
// pushes it onto the main data stack.
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 y3]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2]
func opcodeFromAltStack(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.astack.PopByteArray()
	if err != nil {
		return err
	}
	vm.dstack.PushByteArray(so)

	return nil
}

// opcode2Drop removes the top 2 items from the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1]
func opcode2Drop(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DropN(2)
}

// opcode2Dup duplicates the top 2 items on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2 x3]
func opcode2Dup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(2)
}

// opcode3Dup duplicates the top 3 items on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x1 x2 x3]
func opcode3Dup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(3)
}

// opcode2Over duplicates the 2 items before the top 2 items on the data stack.
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x1 x2 x3 x4 x1 x2]
func opcode2Over(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.OverN(2)
}

// opcode2Rot rotates the top 6 items on the data stack to the left twice.
//
// Stack transformation: [... x1 x2 x3 x4 x5 x6] -> [... x3 x4 x5 x6 x1 x2]
func opcode2Rot(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.RotN(2)
}

// opcode2Swap swaps the top 2 items on the data stack with the 2 that come
// before them.
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x3 x4 x1 x2]
func opcode2Swap(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.SwapN(2)
}

// opcodeIfDup duplicates the top item of the stack if it is not zero.
//
// Stack transformation (x1==0): [... x1] -> [... x1]
// Stack transformation (x1!=0): [... x1] -> [... x1 x1]
func opcodeIfDup(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	// Push copy of data iff it isn't zero
	if asBool(so) {
		vm.dstack.PushByteArray(so)
	}

	return nil
}

// opcodeDepth pushes the depth of the data stack prior to executing this
// opcode, encoded as a number, onto the data stack.
//
// Stack transformation: [...] -> [... <num of items on the stack>]
// Example with 2 items: [x1 x2] -> [x1 x2 2]
// Example with 3 items: [x1 x2 x3] -> [x1 x2 x3 3]
func opcodeDepth(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(vm.dstack.Depth()))
	return nil
}

// opcodeDrop removes the top item from the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2]
func opcodeDrop(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DropN(1)
}

// opcodeDup duplicates the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x3]
func opcodeDup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(1)
}

// opcodeNip removes the item before the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x3]
func opcodeNip(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.NipN(1)
}

// opcodeOver duplicates the item before the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2]
func opcodeOver(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.OverN(1)
}

// opcodePick treats the top item on the data stack as an integer and duplicates
// the item on the stack that number of items back to the top.
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [xn ... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x1 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x2 x1 x0 x2]
func opcodePick(op *opcode, data []byte, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.PickN(val.Int32())
}

// opcodeRoll treats the top item on the data stack as an integer and moves
// the item on the stack that number of items back to the top.
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x1 x0 x2]
func opcodeRoll(op *opcode, data []byte, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.RollN(val.Int32())
}

// opcodeRot rotates the top 3 items on the data stack to the left.
//
// Stack transformation: [... x1 x2 x3] -> [... x2 x3 x1]
func opcodeRot(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.RotN(1)
}

// opcodeSwap swaps the top two items on the stack.
//
// Stack transformation: [... x1 x2] -> [... x2 x1]
func opcodeSwap(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.SwapN(1)
}

// opcodeTuck inserts a duplicate of the top item of the data stack before the
// second-to-top item.
//
// Stack transformation: [... x1 x2] -> [... x2 x1 x2]
func opcodeTuck(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.Tuck()
}

// opcodeSize pushes the size of the top item of the data stack onto the data
// stack.
//
// Stack transformation: [... x1] -> [... x1 len(x1)]
func opcodeSize(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	vm.dstack.PushInt(scriptNum(len(so)))
	return nil
}

// opcodeEqual removes the top 2 items of the data stack, compares them as raw
// bytes, and pushes the result, encoded as a boolean, back to the stack.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeEqual(op *opcode, data []byte, vm *Engine) error {
	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushBool(bytes.Equal(a, b))
	return nil
}

// opcodeEqualVerify is a combination of opcodeEqual and opcodeVerify.
// Specifically, it removes the top 2 items of the data stack, compares them,
// and pushes the result, encoded as a boolean, back to the stack.  Then, it
// examines the top item on the data stack as a boolean value and verifies it
// evaluates to true.  An error is returned if it does not.
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeEqualVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeEqual(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, txscript.ErrEqualVerify)
	}
	return err
}

// opcode1Add treats the top item on the data stack as an integer and replaces
// it with its incremented value (plus 1).
//
// Stack transformation: [... x1 x2] -> [... x1 x2+1]
func opcode1Add(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(m + 1)
	return nil
}

// opcode1Sub treats the top item on the data stack as an integer and replaces
// it with its decremented value (minus 1).
//
// Stack transformation: [... x1 x2] -> [... x1 x2-1]
func opcode1Sub(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	vm.dstack.PushInt(m - 1)

	return nil
}

// opcodeNegate treats the top item on the data stack as an integer and replaces
// it with its negation.
//
// Stack transformation: [... x1 x2] -> [... x1 -x2]
func opcodeNegate(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(-m)
	return nil
}

// opcodeAbs treats the top item on the data stack as an integer and replaces it
// it with its absolute value.
//
// Stack transformation: [... x1 x2] -> [... x1 abs(x2)]
func opcodeAbs(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m < 0 {
		m = -m
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeNot treats the top item on the data stack as an integer and replaces
// it with its "inverted" value (0 becomes 1, non-zero becomes 0).
//
// NOTE: While it would probably make more sense to treat the top item as a
// boolean, and push the opposite, which is really what the intention of this
// opcode is, it is extremely important that is not done because integers are
// interpreted differently than booleans and the consensus rules for this opcode
// dictate the item is interpreted as an integer.
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 0]
func opcodeNot(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m == 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcode0NotEqual treats the top item on the data stack as an integer and
// replaces it with either a 0 if it is zero, or a 1 if it is not zero.
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 1]
func opcode0NotEqual(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m != 0 {
		m = 1
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeAdd treats the top two items on the data stack as integers and replaces
// them with their sum.
//
// Stack transformation: [... x1 x2] -> [... x1+x2]
func opcodeAdd(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v0 + v1)
	return nil
}

// opcodeSub treats the top two items on the data stack as integers and replaces
// them with the result of subtracting the top entry from the second-to-top
// entry.
//
// Stack transformation: [... x1 x2] -> [... x1-x2]
func opcodeSub(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v1 - v0)
	return nil
}

// opcodeBoolAnd treats the top two items on the data stack as integers.  When
// both of them are not zero, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 0]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 0]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolAnd(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 && v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeBoolOr treats the top two items on the data stack as integers.  When
// either of them are not zero, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 1]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 1]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolOr(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 || v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqual treats the top two items on the data stack as integers.  When
// they are equal, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==x2): [... 5 5] -> [... 1]
// Stack transformation (x1!=x2): [... 5 7] -> [... 0]
func opcodeNumEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 == v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqualVerify is a combination of opcodeNumEqual and opcodeVerify.
//
// Specifically, treats the top two items on the data stack as integers.  When
// they are equal, they are replaced with a 1, otherwise a 0.  Then, it examines
// the top item on the data stack as a boolean value and verifies it evaluates
// to true.  An error is returned if it does not.
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeNumEqualVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeNumEqual(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, txscript.ErrNumEqualVerify)
	}
	return err
}

// opcodeNumNotEqual treats the top two items on the data stack as integers.
// When they are NOT equal, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==x2): [... 5 5] -> [... 0]
// Stack transformation (x1!=x2): [... 5 7] -> [... 1]
func opcodeNumNotEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeLessThan treats the top two items on the data stack as integers.  When
// the second-to-top item is less than the top item, they are replaced with a 1,
// otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThan(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeGreaterThan treats the top two items on the data stack as integers.
// When the second-to-top item is greater than the top item, they are replaced
// with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThan(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeLessThanOrEqual treats the top two items on the data stack as integers.
// When the second-to-top item is less than or equal to the top item, they are
// replaced with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThanOrEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 <= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeGreaterThanOrEqual treats the top two items on the data stack as
// integers.  When the second-to-top item is greater than or equal to the top
// item, they are replaced with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThanOrEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 >= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeMin treats the top two items on the data stack as integers and replaces
// them with the minimum of the two.
//
// Stack transformation: [... x1 x2] -> [... min(x1, x2)]
func opcodeMin(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeMax treats the top two items on the data stack as integers and replaces
// them with the maximum of the two.
//
// Stack transformation: [... x1 x2] -> [... max(x1, x2)]
func opcodeMax(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeWithin treats the top 3 items on the data stack as integers.  When the
// value to test is within the specified range (left inclusive), they are
// replaced with a 1, otherwise a 0.
//
// The top item is the max value, the second-top-item is the minimum value, and
// the third-to-top item is the value to test.
//
// Stack transformation: [... x1 min max] -> [... bool]
func opcodeWithin(op *opcode, data []byte, vm *Engine) error {
	maxVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	minVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	x, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if x >= minVal && x < maxVal {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// calcHash calculates the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// opcodeRipemd160 treats the top item of the data stack as raw bytes and
// replaces it with ripemd160(data).
//
// Stack transformation: [... x1] -> [... ripemd160(x1)]
func opcodeRipemd160(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(calcHash(buf, ripemd160.New()))
	return nil
}

// opcodeSha1 treats the top item of the data stack as raw bytes and replaces it
// with sha1(data).
//
// Stack transformation: [... x1] -> [... sha1(x1)]
func opcodeSha1(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha1.Sum(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeSha256 treats the top item of the data stack as raw bytes and replaces
// it with sha256(data).
//
// Stack transformation: [... x1] -> [... sha256(x1)]
func opcodeSha256(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeHash160 treats the top item of the data stack as raw bytes and replaces
// it with ripemd160(sha256(data)).
//
// Stack transformation: [... x1] -> [... ripemd160(sha256(x1))]
func opcodeHash160(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(calcHash(hash[:], ripemd160.New()))
	return nil
}

// opcodeHash256 treats the top item of the data stack as raw bytes and replaces
// it with sha256(sha256(data)).
//
// Stack transformation: [... x1] -> [... sha256(sha256(x1))]
func opcodeHash256(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(chainhash.DoubleHashB(buf))
	return nil
}

// opcodeCodeSeparator stores the current script offset as the most recently
// seen OP_CODESEPARATOR which is used during signature checking.
//
// This opcode does not change the contents of the data stack.
func opcodeCodeSeparator(op *opcode, data []byte, vm *Engine) error {
	vm.lastCodeSep = int(vm.tokenizer.ByteIndex())

	if vm.taprootCtx != nil {
		vm.taprootCtx.codeSepPos = uint32(vm.tokenizer.OpcodePosition())
	} else if vm.witnessProgram == nil &&
		vm.hasFlag(txscript.ScriptVerifyConstScriptCode) {

		// Disable OP_CODESEPARATOR for non-segwit scripts.
		str := "OP_CODESEPARATOR used in non-segwit script"
		return scriptError(txscript.ErrCodeSeparator, str)
	}

	return nil
}

// opcodeCheckSig treats the top 2 items on the stack as a public key and a
// signature and replaces them with a bool which indicates if the signature was
// successfully verified.
//
// The process of verifying a signature requires calculating a signature hash in
// the same way the transaction signer did.  It involves hashing portions of the
// transaction based on the hash type byte (which is the final byte of the
// signature) and the portion of the script starting from the most recent
// OP_CODESEPARATOR (or the beginning of the script if there are none) to the
// end of the script (with any other OP_CODESEPARATORs removed).  Once this
// "script hash" is calculated, the signature is checked using standard
// cryptographic methods against the provided public key.
//
// Stack transformation: [... signature pubkey] -> [... bool]
func opcodeCheckSig(op *opcode, data []byte, vm *Engine) error {
	pkBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	fullSigBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// The signature actually needs to be longer than this, but at
	// least 1 byte is needed for the hash type below.  The full length is
	// checked depending on the script flags and upon parsing the signature.
	//
	// This only applies if tapscript verification isn't active, as this
	// check is done within the sighash itself.
	if vm.taprootCtx == nil && len(fullSigBytes) < 1 {
		vm.dstack.PushBool(false)
		return nil
	}

	var sigVerifier signatureVerifier
	switch {
	// If no witness program is active, then we're verifying under the
	// base consensus rules.
	case vm.witnessProgram == nil:
		sigVerifier, err = newBaseSigVerifier(
			pkBytes, fullSigBytes, vm,
		)
		if err != nil {
			var scriptErr txscript.Error
			if errors.As(err, &scriptErr) {
				return err
			}

			vm.dstack.PushBool(false)
			return nil
		}

	// If the base segwit version is active, then we'll create the verifier
	// that factors in those new consensus rules.
	case vm.isWitnessVersionActive(txscript.BaseSegwitWitnessVersion):
		sigVerifier, err = newBaseSegwitSigVerifier(
			pkBytes, fullSigBytes, vm,
		)
		if err != nil {
			var scriptErr txscript.Error
			if errors.As(err, &scriptErr) {
				return err
			}

			vm.dstack.PushBool(false)
			return nil
		}

	// Otherwise, this is routine tapscript execution.
	case vm.taprootCtx != nil:
		// Account for changes in the sig ops budget after this
		// execution, but only for non-empty signatures.
		if len(fullSigBytes) > 0 {
			if err := vm.taprootCtx.tallysigOp(); err != nil {
				return err
			}
		}

		// Empty public keys immediately cause execution to fail.
		if len(pkBytes) == 0 {
			return scriptError(txscript.ErrTaprootPubkeyIsEmpty, "")
		}

		// If this is tapscript execution, and the signature was
		// actually an empty vector, then we push on an empty vector
		// and continue execution from there, but only if the pubkey
		// isn't empty.
		if len(fullSigBytes) == 0 {
			vm.dstack.PushByteArray([]byte{})
			return nil
		}

		// If the constructor fails immediately, then it's because
		// the public key size is zero, so we'll fail all script
		// execution.
		sigVerifier, err = newBaseTapscriptSigVerifier(
			pkBytes, fullSigBytes, vm,
		)
		if err != nil {
			return err
		}

	default:
		// We skip segwit v1 in isolation here, as the v1 rules aren't
		// used in script execution (for sig verification) and are only
		// part of the top-level key-spend verification which we
		// already skipped.
		//
		// In other words, this path shouldn't ever be reached
		//
		// TODO(roasbeef): return an error?
	}

	result := sigVerifier.Verify()
	valid := result.sigValid

	if vm.hasFlag(txscript.ScriptVerifyConstScriptCode) && result.sigMatch {
		str := "non-const script code"
		return scriptError(txscript.ErrNonConstScriptCode, str)
	}

	switch {
	// For tapscript, and prior execution with null fail active, if the
	// signature is invalid, then this MUST be an empty signature.
	case !valid && vm.taprootCtx != nil && len(fullSigBytes) != 0:
		fallthrough
	case !valid && vm.hasFlag(txscript.ScriptVerifyNullFail) && len(fullSigBytes) > 0:
		str := "signature not empty on failed checksig"
		return scriptError(txscript.ErrNullFail, str)
	}

	vm.dstack.PushBool(valid)
	return nil
}

// opcodeCheckSigVerify is a combination of opcodeCheckSig and opcodeVerify.
// The opcodeCheckSig function is invoked followed by opcodeVerify.  See the
// documentation for each of those opcodes for more details.
//
// Stack transformation: [... signature pubkey] -> [... bool] -> [...]
func opcodeCheckSigVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeCheckSig(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, txscript.ErrCheckSigVerify)
	}
	return err
}

// opcodeCheckSigAdd implements the OP_CHECKSIGADD operation defined in BIP
// 342. This is a replacement for OP_CHECKMULTISIGVERIFY and OP_CHECKMULTISIG
// that lends better to batch sig validation, as well as a possible future of
// signature aggregation across inputs.
//
// The op code takes a public key, an integer (N) and a signature, and returns
// N if the signature was the empty vector, and n+1 otherwise.
//
// Stack transformation: [... pubkey n signature] -> [... n | n+1 ] -> [...]
func opcodeCheckSigAdd(op *opcode, data []byte, vm *Engine) error {
	// This op code can only be used if tapsript execution is active.
	// Before the soft fork, this opcode was marked as an invalid reserved
	// op code.
	if vm.taprootCtx == nil {
		str := fmt.Sprintf("attempt to execute invalid opcode %s", op.name)
		return scriptError(txscript.ErrReservedOpcode, str)
	}

	// Pop the signature, integer n, and public key off the stack.
	pubKeyBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	accumulatorInt, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	sigBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Only non-empty signatures count towards the total tapscript sig op
	// limit.
	if len(sigBytes) != 0 {
		// Account for changes in the sig ops budget after this execution.
		if err := vm.taprootCtx.tallysigOp(); err != nil {
			return err
		}
	}

	// Empty public keys immediately cause execution to fail.
	if len(pubKeyBytes) == 0 {
		return scriptError(txscript.ErrTaprootPubkeyIsEmpty, "")
	}

	// If the signature is empty, then we'll just push the value N back
	// onto the stack and continue from here.
	if len(sigBytes) == 0 {
		vm.dstack.PushInt(accumulatorInt)
		return nil
	}

	// Otherwise, we'll attempt to validate the signature as normal.
	//
	// If the constructor fails immediately, then it's because the public
	// key size is zero, so we'll fail all script execution.
	sigVerifier, err := newBaseTapscriptSigVerifier(
		pubKeyBytes, sigBytes, vm,
	)
	if err != nil {
		return err
	}

	result := sigVerifier.Verify()

	// If the signature is invalid, this we fail execution, as it should
	// have been an empty signature.
	if !result.sigValid {
		str := "signature not empty on failed checksig"
		return scriptError(txscript.ErrNullFail, str)
	}

	// Otherwise, we increment the accumulatorInt by one, and push that
	// back onto the stack.
	vm.dstack.PushInt(accumulatorInt + 1)

	return nil
}

// parsedSigInfo houses a raw signature along with its parsed form and a flag
// for whether or not it has already been parsed.  It is used to prevent parsing
// the same signature multiple times when verifying a multisig.
type parsedSigInfo struct {
	signature       []byte
	parsedSignature *ecdsa.Signature
	parsed          bool
}

// opcodeCheckMultiSig treats the top item on the stack as an integer number of
// public keys, followed by that many entries as raw data representing the public
// keys, followed by the integer number of signatures, followed by that many
// entries as raw data representing the signatures.
//
// Due to a bug in the original Satoshi client implementation, an additional
// dummy argument is also required by the consensus rules, although it is not
// used.  The dummy value SHOULD be an OP_0, although that is not required by
// the consensus rules.  When the ScriptStrictMultiSig flag is set, it must be
// OP_0.
//
// All of the aforementioned stack items are replaced with a bool which
// indicates if the requisite number of signatures were successfully verified.
//
// See the opcodeCheckSigVerify documentation for more details about the process
// for verifying each signature.
//
// Stack transformation:
// [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool]
func opcodeCheckMultiSig(op *opcode, data []byte, vm *Engine) error {
	// If we're doing tapscript execution, then this op code is disabled.
	if vm.taprootCtx != nil {
		str := fmt.Sprintf("OP_CHECKMULTISIG and " +
			"OP_CHECKMULTISIGVERIFY are disabled during " +
			"tapscript execution")
		return scriptError(txscript.ErrTapscriptCheckMultisig, str)
	}

	numKeys, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	numPubKeys := int(numKeys.Int32())
	if numPubKeys < 0 {
		str := fmt.Sprintf("number of pubkeys %d is negative",
			numPubKeys)
		return scriptError(txscript.ErrInvalidPubKeyCount, str)
	}
	if numPubKeys > txscript.MaxPubKeysPerMultiSig {
		str := fmt.Sprintf("too many pubkeys: %d > %d",
			numPubKeys, txscript.MaxPubKeysPerMultiSig)
		return scriptError(txscript.ErrInvalidPubKeyCount, str)
	}
	vm.numOps += numPubKeys
	if vm.numOps > txscript.MaxOpsPerScript {
		str := fmt.Sprintf("exceeded max operation limit of %d",
			txscript.MaxOpsPerScript)
		return scriptError(txscript.ErrTooManyOperations, str)
	}

	pubKeys := make([][]byte, 0, numPubKeys)
	for i := 0; i < numPubKeys; i++ {
		pubKey, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		pubKeys = append(pubKeys, pubKey)
	}

	numSigs, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	numSignatures := int(numSigs.Int32())
	if numSignatures < 0 {
		str := fmt.Sprintf("number of signatures %d is negative",
			numSignatures)
		return scriptError(txscript.ErrInvalidSignatureCount, str)

	}
	if numSignatures > numPubKeys {
		str := fmt.Sprintf("more signatures than pubkeys: %d > %d",
			numSignatures, numPubKeys)
		return scriptError(txscript.ErrInvalidSignatureCount, str)
	}

	signatures := make([]*parsedSigInfo, 0, numSignatures)
	for i := 0; i < numSignatures; i++ {
		signature, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		sigInfo := &parsedSigInfo{signature: signature}
		signatures = append(signatures, sigInfo)
	}

	// A bug in the original Satoshi client implementation means one more
	// stack value than should be used must be popped.  Unfortunately, this
	// buggy behavior is now part of the consensus and a hard fork would be
	// required to fix it.
	dummy, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Since the dummy argument is otherwise not checked, it could be any
	// value which unfortunately provides a source of malleability.  Thus,
	// there is a script flag to force an error when the value is NOT 0.
	if vm.hasFlag(txscript.ScriptStrictMultiSig) && len(dummy) != 0 {
		str := fmt.Sprintf("multisig dummy argument has length %d "+
			"instead of 0", len(dummy))
		return scriptError(txscript.ErrSigNullDummy, str)
	}

	// Get script starting from the most recent OP_CODESEPARATOR.
	script := vm.subScript()

	// Remove the signature in pre version 0 segwit scripts since there is
	// no way for a signature to sign itself.
	if !vm.isWitnessVersionActive(0) {
		for _, sigInfo := range signatures {
			var match bool
			script, match = removeOpcodeByData(script, sigInfo.signature)
			if vm.hasFlag(txscript.ScriptVerifyConstScriptCode) && match {
				str := fmt.Sprintf("got match of %v in %v", sigInfo.signature,
					script)
				return scriptError(txscript.ErrNonConstScriptCode, str)
			}
		}
	}

	success := true
	numPubKeys++
	pubKeyIdx := -1
	signatureIdx := 0
	for numSignatures > 0 {
		// When there are more signatures than public keys remaining,
		// there is no way to succeed since too many signatures are
		// invalid, so exit early.
		pubKeyIdx++
		numPubKeys--
		if numSignatures > numPubKeys {
			success = false
			break
		}

		sigInfo := signatures[signatureIdx]
		pubKey := pubKeys[pubKeyIdx]

		// The order of the signature and public key evaluation is
		// important here since it can be distinguished by an
		// OP_CHECKMULTISIG NOT when the strict encoding flag is set.

		rawSig := sigInfo.signature
		if len(rawSig) == 0 {
			// Skip to the next pubkey if signature is empty.
			continue
		}

		// Split the signature into hash type and signature components.
		hashType := txscript.SigHashType(rawSig[len(rawSig)-1])
		signature := rawSig[:len(rawSig)-1]

		// Only parse and check the signature encoding once.
		var parsedSig *ecdsa.Signature
		if !sigInfo.parsed {
			if err := vm.checkHashTypeEncoding(hashType); err != nil {
				return err
			}
			if err := vm.checkSignatureEncoding(signature); err != nil {
				return err
			}

			// Parse the signature.
			var err error
			if vm.hasFlag(txscript.ScriptVerifyStrictEncoding) ||
				vm.hasFlag(txscript.ScriptVerifyDERSignatures) {

				parsedSig, err = ecdsa.ParseDERSignature(signature)
			} else {
				parsedSig, err = ecdsa.ParseSignature(signature)
			}
			sigInfo.parsed = true
			if err != nil {
				continue
			}
			sigInfo.parsedSignature = parsedSig
		} else {
			// Skip to the next pubkey if the signature is invalid.
			if sigInfo.parsedSignature == nil {
				continue
			}

			// Use the already parsed signature.
			parsedSig = sigInfo.parsedSignature
		}

		if err := vm.checkPubKeyEncoding(pubKey); err != nil {
			return err
		}

		// Parse the pubkey.
		parsedPubKey, err := btcec.ParsePubKey(pubKey)
		if err != nil {
			continue
		}

		// Generate the signature hash based on the signature hash type.
		var hash []byte
		if vm.isWitnessVersionActive(0) {
			var sigHashes *txscript.TxSigHashes
			if vm.hashCache != nil {
				sigHashes = vm.hashCache
			} else {
				sigHashes = txscript.NewTxSigHashes(
					&vm.tx, vm.prevOutFetcher,
				)
			}

			hash, err = txscript.CalcWitnessSigHash(
				script, sigHashes, hashType,
				&vm.tx, vm.txIdx, vm.inputAmount,
			)
			if err != nil {
				return err
			}
		} else {
			hash, err = txscript.CalcSignatureHash(script, hashType, &vm.tx, vm.txIdx)
			if err != nil {
				return err
			}
		}

		var valid bool
		if vm.sigCache != nil {
			var sigHash chainhash.Hash
			copy(sigHash[:], hash)

			valid = vm.sigCache.Exists(sigHash, signature, pubKey)
			if !valid && parsedSig.Verify(hash, parsedPubKey) {
				vm.sigCache.Add(sigHash, signature, pubKey)
				valid = true
			}
		} else {
			valid = parsedSig.Verify(hash, parsedPubKey)
		}

		if valid {
			// PubKey verified, move on to the next signature.
			signatureIdx++
			numSignatures--
		}
	}

	if !success && vm.hasFlag(txscript.ScriptVerifyNullFail) {
		for _, sig := range signatures {
			if len(sig.signature) > 0 {
				str := "not all signatures empty on failed checkmultisig"
				return scriptError(txscript.ErrNullFail, str)
			}
		}
	}

	vm.dstack.PushBool(success)
	return nil
}

// opcodeCheckMultiSigVerify is a combination of opcodeCheckMultiSig and
// opcodeVerify.  The opcodeCheckMultiSig is invoked followed by opcodeVerify.
// See the documentation for each of those opcodes for more details.
//
// Stack transformation:
// [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool] -> [...]
func opcodeCheckMultiSigVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeCheckMultiSig(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, txscript.ErrCheckMultiSigVerify)
	}
	return err
}

// OpcodeByName is a map that can be used to lookup an opcode by its
// human-readable name (OP_CHECKMULTISIG, OP_CHECKSIG, etc).
var OpcodeByName = make(map[string]byte)

func init() {
	// Initialize the opcode name to value map using the contents of the
	// opcode array.  Also add entries for "OP_FALSE", "OP_TRUE", and
	// "OP_NOP2" since they are aliases for "OP_0", "OP_1",
	// and "OP_CHECKLOCKTIMEVERIFY" respectively.
	for _, op := range opcodeArray {
		OpcodeByName[op.name] = op.value
	}
	OpcodeByName["OP_FALSE"] = OP_FALSE
	OpcodeByName["OP_TRUE"] = OP_TRUE
	OpcodeByName["OP_NOP2"] = OP_CHECKLOCKTIMEVERIFY
	OpcodeByName["OP_NOP3"] = OP_CHECKSEQUENCEVERIFY
}

// opcodeInspectInputOutpoint pops the input index from the stack and pushes the outpoint of the current input onto the stack.
// Stack transformation: [... index] -> [... txid index]
func opcodeInspectInputOutpoint(op *opcode, data []byte, vm *Engine) error {
	index, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(index) >= len(vm.tx.TxIn) {
		return scriptError(txscript.ErrInvalidIndex, "input index out of range")
	}

	txIn := vm.tx.TxIn[index]
	txid := make([]byte, 32)
	copy(txid[:32], txIn.PreviousOutPoint.Hash[:])

	vm.dstack.PushByteArray(txid)
	vm.dstack.PushInt(scriptNum(txIn.PreviousOutPoint.Index))
	return nil
}

// opcodeInspectInputValue pops the input index from the stack and pushes the value of the current input onto the stack.
// Stack transformation: [... index] -> [... value]
func opcodeInspectInputValue(op *opcode, data []byte, vm *Engine) error {
	index, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(index) >= len(vm.tx.TxIn) {
		return scriptError(txscript.ErrInvalidIndex, "input index out of range")
	}

	if vm.prevOutFetcher == nil {
		return scriptError(txscript.ErrInvalidIndex, "previous output fetcher not set")
	}

	prevOut := vm.prevOutFetcher.FetchPrevOutput(vm.tx.TxIn[index].PreviousOutPoint)

	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, uint64(prevOut.Value))
	vm.dstack.PushByteArray(value)
	return nil
}

func pushScriptPubKey(scriptPubKey []byte, vm *Engine) error {
	if txscript.IsWitnessProgram(scriptPubKey) {
		version, program, err := txscript.ExtractWitnessProgramInfo(scriptPubKey)
		if err != nil {
			return err
		}

		// push the witness program (2-40 bytes)
		vm.dstack.PushByteArray(program)

		// push the segwit version as a scriptNum
		vm.dstack.PushInt(scriptNum(version))
		return nil
	}

	// non-native segwit, calculate sha256 hash
	hash := sha256.Sum256(scriptPubKey)
	vm.dstack.PushByteArray(hash[:])

	// -1 indicate non-native segwit
	vm.dstack.PushInt(-1)
	return nil
}

// opcodeInspectInputScriptPubkey pops the input index from the stack and pushes the scriptPubKey of the current input onto the stack.
// Stack transformation: [... index] -> [... scriptPubKey]
func opcodeInspectInputScriptPubkey(op *opcode, data []byte, vm *Engine) error {
	index, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(index) >= len(vm.tx.TxIn) {
		return scriptError(txscript.ErrInvalidIndex, "input index out of range")
	}

	if vm.prevOutFetcher == nil {
		return scriptError(txscript.ErrInvalidIndex, "previous output fetcher not set")
	}

	prevOut := vm.prevOutFetcher.FetchPrevOutput(vm.tx.TxIn[index].PreviousOutPoint)
	if prevOut == nil {
		return scriptError(txscript.ErrInvalidIndex, "previous output not found")
	}

	return pushScriptPubKey(prevOut.PkScript, vm)
}

// opcodeInspectInputSequence pops the input index from the stack and pushes the sequence number of the current input onto the stack.
// Stack transformation: [...] -> [... sequence]
func opcodeInspectInputSequence(op *opcode, data []byte, vm *Engine) error {
	index, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(index) >= len(vm.tx.TxIn) {
		return scriptError(txscript.ErrInvalidIndex, "input index out of range")
	}

	sequence := make([]byte, 4)
	binary.LittleEndian.PutUint32(sequence, vm.tx.TxIn[index].Sequence)
	vm.dstack.PushByteArray(sequence)
	return nil
}

// opcodePushCurrentInputIndex pushes the current input index onto the stack.
// Stack transformation: [...] -> [... index]
func opcodePushCurrentInputIndex(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(vm.txIdx))
	return nil
}

// opcodeInspectOutputValue pops the output index from the stack and pushes the value of the output onto the stack.
// Stack transformation: [... index] -> [... value]
func opcodeInspectOutputValue(op *opcode, data []byte, vm *Engine) error {
	index, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(index) >= len(vm.tx.TxOut) {
		return scriptError(txscript.ErrInvalidIndex, "output index out of range")
	}

	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, uint64(vm.tx.TxOut[index].Value))
	vm.dstack.PushByteArray(value)
	return nil
}

// opcodeInspectOutputScriptPubkey pushes the scriptPubKey of the output at the given index onto the stack.
// Stack transformation: [... index] -> [... scriptPubKey]
func opcodeInspectOutputScriptPubkey(op *opcode, data []byte, vm *Engine) error {
	index, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(index) >= len(vm.tx.TxOut) {
		return scriptError(txscript.ErrInvalidIndex, "output index out of range")
	}

	return pushScriptPubKey(vm.tx.TxOut[index].PkScript, vm)
}

// opcodeInspectVersion pushes the transaction version onto the stack.
// Stack transformation: [...] -> [... version]
func opcodeInspectVersion(op *opcode, data []byte, vm *Engine) error {
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, uint32(vm.tx.Version))
	vm.dstack.PushByteArray(version)
	return nil
}

// opcodeInspectLocktime pushes the transaction locktime onto the stack.
// Stack transformation: [...] -> [... locktime]
func opcodeInspectLocktime(op *opcode, data []byte, vm *Engine) error {
	locktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktime, vm.tx.LockTime)
	vm.dstack.PushByteArray(locktime)
	return nil
}

// opcodeInspectNumInputs pushes the number of inputs in the transaction onto the stack.
// Stack transformation: [...] -> [... numInputs]
func opcodeInspectNumInputs(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(len(vm.tx.TxIn)))
	return nil
}

// opcodeInspectNumOutputs pushes the number of outputs in the transaction onto the stack.
// Stack transformation: [...] -> [... numOutputs]
func opcodeInspectNumOutputs(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(len(vm.tx.TxOut)))
	return nil
}

// opcodeTxWeight pushes the transaction weight onto the stack.
// Stack transformation: [...] -> [... weight]
func opcodeTxWeight(op *opcode, data []byte, vm *Engine) error {
	weight := make([]byte, 4)
	binary.LittleEndian.PutUint32(weight, uint32(vm.tx.SerializeSizeStripped()*4))
	vm.dstack.PushByteArray(weight)
	return nil
}

// opcodeCat concatenates two byte arrays.
// Stack transformation: [... x1 x2] -> [... x1|x2]
func opcodeCat(op *opcode, data []byte, vm *Engine) error {
	x2, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	x1, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(append(x1, x2...))
	return nil
}

// opcodeSubstr returns a portion of a byte array.
// Stack transformation: [... x n size] -> [... x[n:n+size]]
func opcodeSubstr(op *opcode, data []byte, vm *Engine) error {
	size, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	begin, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	x, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Ensure bounds are valid
	if begin < 0 || size < 0 || begin+size > scriptNum(len(x)) {
		return scriptError(txscript.ErrInvalidIndex, "invalid substring parameters")
	}

	vm.dstack.PushByteArray(x[begin : begin+size])
	return nil
}

// opcodeLeft returns the first N bytes of a byte array.
// Stack transformation: [... x n] -> [... x[:n]]
func opcodeLeft(op *opcode, data []byte, vm *Engine) error {
	n, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	x, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Ensure bounds are valid
	if n < 0 || n > scriptNum(len(x)) {
		return scriptError(txscript.ErrInvalidIndex, "invalid left index")
	}

	vm.dstack.PushByteArray(x[:n])
	return nil
}

// opcodeRight returns the last N bytes of a byte array.
// Stack transformation: [... x n] -> [... x[len(x)-n:]]
func opcodeRight(op *opcode, data []byte, vm *Engine) error {
	n, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	x, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Ensure bounds are valid
	if n < 0 || n > scriptNum(len(x)) {
		return scriptError(txscript.ErrInvalidIndex, "invalid right index")
	}

	vm.dstack.PushByteArray(x[len(x)-int(n):])
	return nil
}

// opcodeInvert performs a bitwise NOT operation.
// Stack transformation: [... x] -> [... ~x]
func opcodeInvert(op *opcode, data []byte, vm *Engine) error {
	x, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	result := make([]byte, len(x))
	for i := range x {
		result[i] = ^x[i]
	}

	vm.dstack.PushByteArray(result)
	return nil
}

// opcodeAnd performs a bitwise AND operation.
// Stack transformation: [... x1 x2] -> [... x1&x2]
func opcodeAnd(op *opcode, data []byte, vm *Engine) error {
	x2, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	x1, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	if len(x1) != len(x2) {
		return scriptError(txscript.ErrInvalidStackOperation, "mismatched operand sizes for AND")
	}

	result := make([]byte, len(x1))
	for i := range x1 {
		result[i] = x1[i] & x2[i]
	}

	vm.dstack.PushByteArray(result)
	return nil
}

// opcodeOr performs a bitwise OR operation.
// Stack transformation: [... x1 x2] -> [... x1|x2]
func opcodeOr(op *opcode, data []byte, vm *Engine) error {
	x2, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	x1, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	if len(x1) != len(x2) {
		return scriptError(txscript.ErrInvalidStackOperation, "mismatched operand sizes for OR")
	}

	result := make([]byte, len(x1))
	for i := range x1 {
		result[i] = x1[i] | x2[i]
	}

	vm.dstack.PushByteArray(result)
	return nil
}

// opcodeXor performs a bitwise XOR operation.
// Stack transformation: [... x1 x2] -> [... x1^x2]
func opcodeXor(op *opcode, data []byte, vm *Engine) error {
	x2, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	x1, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	if len(x1) != len(x2) {
		return scriptError(txscript.ErrInvalidStackOperation, "mismatched operand sizes for XOR")
	}

	result := make([]byte, len(x1))
	for i := range x1 {
		result[i] = x1[i] ^ x2[i]
	}

	vm.dstack.PushByteArray(result)
	return nil
}

// opcode2Mul multiplies a number by 2.
// Stack transformation: [... x] -> [... x*2]
func opcode2Mul(op *opcode, data []byte, vm *Engine) error {
	x, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(x * 2)
	return nil
}

// opcode2Div divides a number by 2.
// Stack transformation: [... x] -> [... x/2]
func opcode2Div(op *opcode, data []byte, vm *Engine) error {
	x, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(x / 2)
	return nil
}

// opcodeMul multiplies two numbers.
// Stack transformation: [... x1 x2] -> [... x1*x2]
func opcodeMul(op *opcode, data []byte, vm *Engine) error {
	x2, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	x1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(x1 * x2)
	return nil
}

// opcodeDiv divides two numbers.
// Stack transformation: [... x1 x2] -> [... x1/x2]
func opcodeDiv(op *opcode, data []byte, vm *Engine) error {
	x2, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	x1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if x2 == 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "division by zero")
	}

	vm.dstack.PushInt(x1 / x2)
	return nil
}

// opcodeMod returns the remainder after division.
// Stack transformation: [... x1 x2] -> [... x1%x2]
func opcodeMod(op *opcode, data []byte, vm *Engine) error {
	x2, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	x1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if x2 == 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "modulo by zero")
	}

	vm.dstack.PushInt(x1 % x2)
	return nil
}

// opcodeLshift performs a left shift operation.
// Stack transformation: [... x n] -> [... x<<n]
func opcodeLshift(op *opcode, data []byte, vm *Engine) error {
	n, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if n < 0 {
		return scriptError(txscript.ErrInvalidIndex, "negative shift count")
	}

	x, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Convert to big integer for arbitrary precision shift
	value := new(big.Int).SetBytes(x)
	result := value.Lsh(value, uint(n))

	vm.dstack.PushByteArray(result.Bytes())
	return nil
}

// opcodeRshift performs a right shift operation.
// Stack transformation: [... x n] -> [... x>>n]
func opcodeRshift(op *opcode, data []byte, vm *Engine) error {
	n, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if n < 0 {
		return scriptError(txscript.ErrInvalidIndex, "negative shift count")
	}

	x, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Convert to big integer for arbitrary precision shift
	value := new(big.Int).SetBytes(x)
	result := value.Rsh(value, uint(n))

	vm.dstack.PushByteArray(result.Bytes())
	return nil
}

// opcodeChecksigFromStack verifies a signature against a public key and message from the stack.
// Stack transformation: [... sig msg pubkey] -> [... bool]
func opcodeChecksigFromStack(op *opcode, data []byte, vm *Engine) error {
	pubKey, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	message, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	signature, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(signature) == 0 {
		// push empty vector
		vm.dstack.PushByteArray([]byte{})
		return nil
	}

	if len(pubKey) == 0 {
		return scriptError(txscript.ErrTaprootPubkeyIsEmpty, "public key is empty")
	}

	if len(pubKey) != 32 {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid public key size, expected 32 bytes")
	}

	pubKeyObj, err := schnorr.ParsePubKey(pubKey)
	if err != nil {
		return err
	}

	signatureObj, err := schnorr.ParseSignature(signature)
	if err != nil {
		return err
	}

	valid := signatureObj.Verify(message, pubKeyObj)
	if !valid {
		return scriptError(txscript.ErrNullFail, "schnorr signature verification failed")
	}

	// success
	vm.dstack.PushInt(1)
	return nil
}

// opcodeAdd64 performs 64-bit addition with overflow checking
// Stack transformation: [... a b] -> [... sum 1] (no overflow) or [... a b 0] (overflow)
func opcodeAdd64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_ADD64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_ADD64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	sum, overflow := mathutil.AddOverflowInt64(aVal, bVal)
	if overflow {
		// overflow : restore original operands and push 0
		vm.dstack.PushByteArray(a)
		vm.dstack.PushByteArray(b)
		vm.dstack.PushInt(0)
		return nil
	}

	// no overflow : push result and success scriptNum
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, uint64(sum))
	vm.dstack.PushByteArray(result)
	vm.dstack.PushInt(1)
	return nil
}

// opcodeSub64 performs 64-bit subtraction with overflow checking
// Stack transformation: [... a b] -> [... diff 1] (no overflow) or [... a b 0] (overflow)
func opcodeSub64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_SUB64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_SUB64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	diff, overflow := mathutil.SubOverflowInt64(aVal, bVal)
	if overflow {
		// overflow : restore original operands and push 0
		vm.dstack.PushByteArray(a)
		vm.dstack.PushByteArray(b)
		vm.dstack.PushInt(0)
		return nil
	}

	// no overflow : push result and success scriptNum
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, uint64(diff))
	vm.dstack.PushByteArray(result)
	vm.dstack.PushInt(1)
	return nil
}

// opcodeMul64 performs 64-bit multiplication with overflow checking
// Stack transformation: [... a b] -> [... product 1] (no overflow) or [... a b 0] (overflow)
func opcodeMul64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_MUL64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_MUL64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	product, overflow := mathutil.MulOverflowInt64(aVal, bVal)
	if overflow {
		// overflow : restore original operands and push 0
		vm.dstack.PushByteArray(a)
		vm.dstack.PushByteArray(b)
		vm.dstack.PushInt(0)
		return nil
	}

	// no overflow : push result and success scriptNum
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, uint64(product))
	vm.dstack.PushByteArray(result)
	vm.dstack.PushInt(1)
	return nil
}

// opcodeDiv64 performs 64-bit division with overflow checking
// Stack transformation: [... a b] -> [... remainder quotient 1] (no overflow) or [... a b 0] (overflow)
func opcodeDiv64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_DIV64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_DIV64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	if bVal == 0 || (aVal == math.MinInt64 && bVal == -1) {
		// division by zero or overflow, restore original operands and push 0
		vm.dstack.PushByteArray(a)
		vm.dstack.PushByteArray(b)
		vm.dstack.PushInt(0)
		return nil
	}

	quotient := aVal / bVal
	remainder := aVal % bVal

	// ensure remainder is non-negative and less than |b|
	if remainder < 0 {
		remainder += int64(math.Abs(float64(bVal)))
		quotient -= 1
	}

	remainderBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(remainderBytes, uint64(remainder))
	vm.dstack.PushByteArray(remainderBytes)

	quotientBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(quotientBytes, uint64(quotient))
	vm.dstack.PushByteArray(quotientBytes)

	vm.dstack.PushInt(1)
	return nil
}

// opcodeNeg64 performs 64-bit negation with overflow checking
// Stack transformation: [... a] -> [... -a 1] (no overflow) or [... a 0] (overflow)
func opcodeNeg64(op *opcode, data []byte, vm *Engine) error {
	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_NEG64 requires 8-byte operand")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))

	product, overflow := mathutil.MulOverflowInt64(aVal, -1)
	if overflow {
		// overflow : restore original operand and push 0
		vm.dstack.PushByteArray(a)
		vm.dstack.PushInt(0)
		return nil
	}

	// no overflow : push result and success scriptNum
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, uint64(product))
	vm.dstack.PushByteArray(result)
	vm.dstack.PushInt(1)
	return nil
}

// opcodeLessThan64 performs 64-bit less than comparison
// Stack transformation: [... a b] -> [... bool]
func opcodeLessThan64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_LESSTHAN64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_LESSTHAN64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	vm.dstack.PushBool(aVal < bVal)
	return nil
}

// opcodeLessThanOrEqual64 performs 64-bit less than or equal comparison
// Stack transformation: [... a b] -> [... bool]
func opcodeLessThanOrEqual64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_LESSTHANOREQUAL64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_LESSTHANOREQUAL64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	vm.dstack.PushBool(aVal <= bVal)
	return nil
}

// opcodeGreaterThan64 performs 64-bit greater than comparison
// Stack transformation: [... a b] -> [... bool]
func opcodeGreaterThan64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_GREATERTHAN64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_GREATERTHAN64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	vm.dstack.PushBool(aVal > bVal)
	return nil
}

// opcodeGreaterThanOrEqual64 performs 64-bit greater than or equal comparison
// Stack transformation: [... a b] -> [... bool]
func opcodeGreaterThanOrEqual64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_GREATERTHANOREQUAL64 requires 8-byte operands")
	}

	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(a) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_GREATERTHANOREQUAL64 requires 8-byte operands")
	}

	aVal := int64(binary.LittleEndian.Uint64(a))
	bVal := int64(binary.LittleEndian.Uint64(b))

	vm.dstack.PushBool(aVal >= bVal)
	return nil
}

// opcodeScriptNumToLE64 converts a minimal CScriptNum to an 8-byte signed LE number
// Stack transformation: [... num] -> [... le64]
func opcodeScriptNumToLE64(op *opcode, data []byte, vm *Engine) error {
	num, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, uint64(int64(num)))
	vm.dstack.PushByteArray(result)
	return nil
}

// opcodeLE64ToScriptNum converts an 8-byte signed LE number to a minimal CScriptNum
// Stack transformation: [... le64] -> [... num]
func opcodeLE64ToScriptNum(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 8 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_LE64TOSCRIPTNUM requires 8-byte operand")
	}

	val := int64(binary.LittleEndian.Uint64(b))
	vm.dstack.PushInt(scriptNum(val))
	return nil
}

// opcodeLE32ToLE64 converts a 4-byte unsigned LE number to an 8-byte signed LE number
// Stack transformation: [... le32] -> [... le64]
func opcodeLE32ToLE64(op *opcode, data []byte, vm *Engine) error {
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(b) != 4 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_LE32TOLE64 requires 4-byte operand")
	}

	val := uint32(binary.LittleEndian.Uint32(b))
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, uint64(val))
	vm.dstack.PushByteArray(result)
	return nil
}

// opcodeECMulScalarVerify verifies that Q = k*P where k is a 32-byte big endian scalar
// and P, Q are compressed EC points on the secp256k1 curve.
// Stack transformation: [... k P Q] -> [...]
func opcodeECMulScalarVerify(op *opcode, data []byte, vm *Engine) error {
	Q, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	P, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	if len(k) != 32 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_ECMULSCALARVERIFY requires 32-byte scalar")
	}

	pubKeyP, err := secp.ParsePubKey(P)
	if err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid point P")
	}

	var scalar secp.ModNScalar
	if overflow := scalar.SetByteSlice(k); overflow {
		return scriptError(txscript.ErrInvalidStackOperation, "scalar k is outside of curve order")
	}

	var point secp.JacobianPoint
	point.X.SetByteSlice(pubKeyP.X().Bytes())
	point.Y.SetByteSlice(pubKeyP.Y().Bytes())
	point.Z.SetInt(1)

	// calculate k*P
	var result secp.JacobianPoint
	secp.ScalarMultNonConst(&scalar, &point, &result)
	result.ToAffine()

	kP := secp.NewPublicKey(&result.X, &result.Y)

	// verify Q == k*P by comparing their serialized compressed forms
	if !bytes.Equal(Q, kP.SerializeCompressed()) {
		return scriptError(txscript.ErrInvalidStackOperation, "Q != k*P")
	}

	return nil
}

// opcodeTweakVerify verifies that Q = P + k*G where P is a 32-byte X-only internal key,
// k is a 32-byte big endian scalar, Q is a 33-byte compressed point, and G is the generator point.
// Stack transformation: [... P k Q] -> [...]
func opcodeTweakVerify(op *opcode, data []byte, vm *Engine) error {
	Q, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	P, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	if len(P) != 32 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_TWEAKVERIFY requires 32-byte X-only key")
	}

	if len(k) != 32 {
		return scriptError(txscript.ErrInvalidStackOperation, "OP_TWEAKVERIFY requires 32-byte scalar")
	}

	var scalar secp.ModNScalar
	if overflow := scalar.SetByteSlice(k); overflow {
		return scriptError(txscript.ErrInvalidStackOperation, "scalar k is outside of curve order")
	}

	var kG secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&scalar, &kG)
	kG.ToAffine()

	var px secp.FieldVal
	if overflow := px.SetByteSlice(P); overflow {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid X-only key P")
	}

	var py secp.FieldVal
	if !secp.DecompressY(&px, false, &py) {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid X-only key P")
	}

	var pointP secp.JacobianPoint
	pointP.X = px
	pointP.Y = py
	pointP.Z.SetInt(1)

	var result secp.JacobianPoint
	secp.AddNonConst(&pointP, &kG, &result)
	result.ToAffine()

	tweakedKey := secp.NewPublicKey(&result.X, &result.Y)

	// verify Q == P + k*G by comparing their serialized compressed forms
	if !bytes.Equal(Q, tweakedKey.SerializeCompressed()) {
		return scriptError(txscript.ErrInvalidStackOperation, "Q != P + k*G")
	}

	return nil
}

// opcodeSha256Initialize pops a bytestring and pushes a SHA256 context created by adding
// the bytestring to the initial SHA256 context.
func opcodeSha256Initialize(op *opcode, _ []byte, vm *Engine) error {
	data, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to write to SHA256 context")
	}

	var state bytes.Buffer
	if err := gob.NewEncoder(&state).Encode(h); err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to save hash state")
	}

	vm.dstack.PushByteArray(state.Bytes())
	return nil
}

// opcodeSha256Update pops a bytestring and SHA256 context, then pushes an updated
// context by adding the bytestring to the data stream being hashed.
func opcodeSha256Update(op *opcode, _ []byte, vm *Engine) error {
	data, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	state, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	h := sha256.New()
	if err := gob.NewDecoder(bytes.NewReader(state)).Decode(h); err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to load hash state")
	}

	if _, err := h.Write(data); err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to write data to SHA256")
	}

	var newState bytes.Buffer
	if err := gob.NewEncoder(&newState).Encode(h); err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to save hash state")
	}

	vm.dstack.PushByteArray(newState.Bytes())
	return nil
}

// opcodeSha256Finalize pops a bytestring and SHA256 context, then pushes the final
// SHA256 hash value after adding the bytestring and completing the padding.
func opcodeSha256Finalize(op *opcode, _ []byte, vm *Engine) error {
	data, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	state, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	h := sha256.New()
	if err := gob.NewDecoder(bytes.NewReader(state)).Decode(h); err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to load hash state")
	}
	if _, err := h.Write(data); err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to write data to SHA256")
	}

	vm.dstack.PushByteArray(h.Sum(nil))
	return nil
}
