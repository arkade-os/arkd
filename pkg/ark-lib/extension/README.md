# extension

Package `extension` encodes and decodes ark extension blobs carried in Bitcoin `OP_RETURN` outputs.

```
OP_RETURN  |  <push>  |  ARK (3 bytes)  |  [ type (1 byte) | varint(len) | data ]...
```

The entire content after `OP_RETURN` is a single Bitcoin script data push. The push opcode is chosen automatically based on payload length:

| Payload size | Push encoding |
|---|---|
| 1 – 75 bytes | `OP_DATA_n` (1-byte length prefix) |
| 76 – 255 bytes | `OP_PUSHDATA1` + 1-byte length |
| 256 – 65535 bytes | `OP_PUSHDATA2` + 2-byte little-endian length |
| 65536+ bytes | `OP_PUSHDATA4` + 4-byte little-endian length |

- **Magic prefix** – the ASCII bytes `ARK` (`0x41 0x52 0x4B`) identify the output as an ark extension.
- **Packets** – one or more typed data records follow the magic. Each record is:
  - 1-byte packet type tag
  - unsigned-varint length of the payload
  - raw payload bytes

Duplicate packet type tags are rejected. An extension with no packets is also rejected.

## Packet types

| Type | Constant | Description |
|------|----------|-------------|
| `0`  | `asset.PacketType` | Asset metadata packet (see `pkg/ark-lib/asset`) |
| any other | `UnknownPacket` | Tolerated and round-tripped opaquely |

## API

```go
// Parse from raw script bytes
ext, err := extension.NewExtensionFromBytes(script)

// Parse from a transaction (searches all outputs)
ext, err := extension.NewExtensionFromTx(tx)

// Check without parsing
ok := extension.IsExtension(script)

// Serialize back to script bytes
script, err := ext.Serialize()

// Build a wire.TxOut ready for inclusion in a transaction
txOut, err := ext.TxOut()

// Retrieve the embedded asset packet (nil if absent)
ap := ext.GetAssetPacket()
```

## Implementing a new packet type

Implement the `Packet` interface:

```go
type Packet interface {
    Type() uint8
    Serialize() ([]byte, error)
}
```

Then add a case to `parsePacket` in `extension.go` so the new type is recognised during decoding.
