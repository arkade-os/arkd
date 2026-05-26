# txfilter

The `txfilter` package provides CEL (Common Expression Language) based filters
that the indexer evaluates against a parsed Bitcoin transaction to decide
whether a subscription should receive an event. Filters are typically supplied
by clients through `Indexer.GetSubscription` / `UpdateSubscription`.

CEL language definition:
https://github.com/google/cel-spec/blob/master/doc/langdef.md#list-of-standard-definitions

## Overview

A `Filter` is a compiled CEL program that must return a `bool`. The indexer
parses each transaction once per event, lifts it into a `Tx` envelope, and runs
every listener's filters against that envelope. A listener receives the event
when any of its filters evaluates to `true`.

## CEL Environment

The environment exposes a single variable, `tx`, of type `txfilter.Tx`.

### Variable

| Variable | Type | Description |
|----------|------|-------------|
| `tx.extension` | `map<int, string>` | ARK OP_RETURN extension contents, keyed by packet type. Values are hex-encoded packet payloads. Only set when the transaction carries an ARK OP_RETURN extension. |

`tx.extension` is treated as unset when the transaction does not carry an ARK
OP_RETURN extension, so `has(tx.extension)` is the canonical presence guard.

## Available Functions

In addition to the [CEL standard library](https://github.com/google/cel-spec/blob/master/doc/langdef.md#list-of-standard-definitions),
the environment provides:

### `hasPacket(extension: map<int, string>, packetType: int) -> bool`

Returns `true` when `extension` contains an entry whose key equals
`packetType`. Equivalent to `packetType in extension`, but explicit and
type-checked.

**Example:**
```cel
has(tx.extension) && hasPacket(tx.extension, 0x42)
```

## Usage

### Compiling and evaluating a filter

```go
f, err := txfilter.Parse("has(tx.extension) && hasPacket(tx.extension, 0x42)")
if err != nil {
    // handle compile error
}

tx, err := txfilter.NewTx(rawTx) // rawTx is a *wire.MsgTx
if err != nil {
    // handle parse error
}

matched, err := f.Eval(tx)
if err != nil {
    // handle evaluation error
}
```

`NewTx` returns an empty `Tx` (no extension) when the transaction does not
carry an ARK OP_RETURN, so a filter referencing `tx.extension` simply evaluates
to `false` in that case rather than producing an error.

## Example Filters

**Match any transaction that carries an ARK extension:**
```cel
has(tx.extension)
```

**Match a specific packet type:**
```cel
has(tx.extension) && hasPacket(tx.extension, 0x42)
```

**Match either of two packet types:**
```cel
has(tx.extension) && (hasPacket(tx.extension, 0x01) || hasPacket(tx.extension, 0x02))
```

**Match a packet with a specific hex-encoded payload:**
```cel
has(tx.extension) && tx.extension[0x42] == 'deadbeef'
```

**Match extensions carrying more than one packet:**
```cel
has(tx.extension) && size(tx.extension) > 1
```

## Return Type

All filter expressions must return a `bool`. Expressions that compile to any
other type are rejected by `Parse`.
