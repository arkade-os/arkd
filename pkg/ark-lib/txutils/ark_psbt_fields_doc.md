# Ark PSBT Fields Documentation

_This document describes the custom PSBT (Partially Signed Bitcoin Transaction) fields used by the Ark protocol. These fields extend the standard PSBT format defined in [BIP 174](https://bips.dev/174/) to support Ark specific functionalities._

### Motivation

Ark transactions require additional metadata beyond what standard PSBT fields provide. The custom fields defined here enable:

1. **Reveal taproot tree on input**: Embedding taproot script trees for complex spending conditions is [currently specified for output](https://bips.dev/371/). We extended it to input.
2. **Relative Time-lock Coordination**: Specifying relative locktimes for CSV (CheckSequenceVerify) spending conditions.
3. **Musig2 Coordination**: Specify musig2 cosigner public keys with proper ordering.
4. **Custom Witness Data**: Supporting additional witness elements for complex script execution.

## Specification

**Ark PSBT fields use the standard PSBT unknown field mechanism with a custom key type identifier: the key type `222` (0xDE) to distinguish them from other protocol extensions.**

### Input Fields

| Name | Type | Key | Description | Value |
|------------|-----|-----|-------------|--------------|
| `taptree` | `0xDE` | `0x74617074726565` ("taptree") | A list of tapscript leaves | {<8-bit uint depth> <8-bit uint leaf version> }* |
| `expiry` | `0xDE` | `0x657870697279` ("expiry") | Relative locktime for [CSV](https://bips.dev/68/) spending condition | [BIP68](https://bips.dev/68/) sequence encoding |
| `cosigner` | `0xDE` | `0x636F7369676E6572` ("cosigner") + `<uint32_key_index>` | Indexed musig2 cosigner public key | 33 bytes compressed public key |
| `condition` | `0xDE` | `0x636F6E646974696F6E` ("condition") | Custom witness elements | raw witness bytes |

## `taptree` Field

**Purpose**: Embeds a taproot script tree associated with an input.

**Key Format**: `0xDE` + `"taptree"` (7 bytes)

**Value Format**: TapTree encoding (variable length)

The TapTree is encoded as a sequence of tapscript leaves, where each leaf contains:
- Depth (1 byte): Always 1 for single-level trees (TODO: allow multiple depth)
- Leaf version (1 byte): Always tapscript version (0xC0)
- Script length (compact size): Length of the script in bytes
- Script bytes: The actual tapscript

**Example**:
```
Key: 0xDE 0x74 0x61 0x70 0x74 0x72 0x65 0x65 ("taptree")
Value: [1(depth)][0xC0(version)][script1_len][script1_bytes][1(depth)][0xC0(version)][script2_len][script2_bytes]...
```

## `expiry` Field

**Purpose**: Specifies a relative locktime (CSV) condition for the input.

**Key Format**: `0xDE` + `"expiry"` (6 bytes)

**Value Format**: [BIP68](https://bips.dev/68/) sequence encoding (1-5 bytes, little-endian)

**Example**:
```
Key: 0xDE 0x65 0x78 0x70 0x69 0x72 0x79 ("expiry")
Value: [sequence_bytes] (e.g., 0x80 0x96 0x98 for 10000 blocks)
```

## `cosigner` Field

**Purpose**: Associates a cosigner public key with an input for multi-signature coordination.

**Key Format**: `0xDE` + `"cosigner"` + `<uint32_key_index>` (11 bytes)

**Value Format**: Compressed public key (33 bytes)

The index is encoded as a 4-byte big-endian integer appended to the base key. This allows multiple cosigner fields per input, each with a unique index for proper ordering.

**Example**:
```
Key: 0xDE 0x63 0x6F 0x73 0x69 0x67 0x6E 0x65 0x72 0x00 0x00 0x00 0x01 ("cosigner" + index 1)
Value: [33-byte compressed public key]
```

## `condition` Field

**Purpose**: Provides additional witness elements for custom script execution.

**Key Format**: `0xDE` + `"condition"` (9 bytes)

**Value Format**: TxWitness encoding (variable length)

The witness is encoded using the standard PSBT witness format:
- Number of witness elements (compact size)
- For each element: length (compact size) + data

**Example**:
```
Key: 0xDE 0x63 0x6F 0x6E 0x64 0x69 0x74 0x69 0x6F 0x6E ("condition")
Value: [witness_encoding]
```

## Reference Implementation

The reference implementation is available in the Ark codebase at:
- `pkg/ark-lib/txutils/psbt_fields.go` - Core field definitions and encoding/decoding
- `pkg/ark-lib/txutils/taptree.go` - TapTree encoding/decoding
- `pkg/ark-lib/locktime.go` - RelativeLocktime handling

