# arkfee

The `arkfee` package provides fee estimation for Ark intents using CEL (Common Expression Language) expressions. It allows you to define custom fee calculation logic for both input and output operations.

CEL language definition:
https://github.com/google/cel-spec/blob/master/doc/langdef.md#list-of-standard-definitions

## Overview

The package provides an `Estimator` that can evaluate CEL expressions to calculate fees based on input and output characteristics. Each estimator can have four separate programs:
- **Intent Offchain Input Program**: Evaluated for each offchain input (vtxo) in an intent
- **Intent Onchain Input Program**: Evaluated for each onchain input (boarding) in an intent
- **Intent Offchain Output Program**: Evaluated for each offchain output (vtxo) in an intent
- **Intent Onchain Output Program**: Evaluated for each onchain output (collaborative exit) in an intent

The total fee is the sum of all input fees plus all output fees.

## CEL Environments

The package provides three CEL environments, each with their own set of available variables and functions.

### IntentOffchainInputEnv

Used for evaluating offchain input (vtxo) fee calculations. Available variables:

| Variable | Type | Description |
|----------|------|-------------|
| `amount` | `double` | Amount in satoshis |
| `expiry` | `double` | Expiry date in Unix timestamp seconds (only available if input has an expiry) |
| `birth` | `double` | Birth date in Unix timestamp seconds (only available if input has a birth time) |
| `weight` | `double` | Weighted liquidity lockup ratio of a vtxo |
| `inputType` | `string` | Type of the input: `'vtxo'`, `'recoverable'`, or `'note'` |

### IntentOnchainInputEnv

Used for evaluating onchain input (boarding) fee calculations. Available variables:

| Variable | Type | Description |
|----------|------|-------------|
| `amount` | `double` | Amount in satoshis |

### IntentOutputEnv

Used for evaluating output fee calculations. Available variables:

| Variable | Type | Description |
|----------|------|-------------|
| `amount` | `double` | Amount in satoshis |
| `script` | `string` | Hex encoded pkscript |

## Available Functions

All environments provide the following functions:

### `now() -> double`

Returns the current Unix timestamp in seconds.

**Example:**
```cel
expiry - now() < double(duration('5m').getSeconds()) ? 0.0 : amount / 2.0
```

## Usage

### Creating an Estimator

```go
intentFees := arkfee.IntentFees{
    IntentOffchainInputProgram:  "inputProgram",
    IntentOnchainInputProgram:   "onchainInputProgram",
    IntentOffchainOutputProgram: "offchainOutputProgram",
    IntentOnchainOutputProgram:  "onchainOutputProgram",
}
estimator, err := arkfee.New(intentFees)
if err != nil {
    // handle error
}
```

All programs are optional. If a program is empty, the corresponding fee evaluation will return 0.

### Evaluating Fees

```go
// Evaluate fee for a single offchain input
offchainInputFee, err := estimator.EvalOffchainInput(arkfee.OffchainInput{
    Amount: 10000,
    Expiry: time.Now().Add(time.Hour),
    Birth:  time.Now().Add(-10 * time.Minute),
    Type:   arkfee.VtxoTypeVtxo,
    Weight: 1.0,
})

// Evaluate fee for a single onchain input
onchainInputFee, err := estimator.EvalOnchainInput(arkfee.OnchainInput{
    Amount: 5000,
})

// Evaluate fee for a single offchain output
offchainOutputFee, err := estimator.EvalOffchainOutput(arkfee.Output{
    Amount: 3000,
    Script: "0014...",
})

// Evaluate fee for a single onchain output
onchainOutputFee, err := estimator.EvalOnchainOutput(arkfee.Output{
    Amount: 2000,
    Script: "0014...",
})

// Evaluate total fee for multiple inputs and outputs
totalFee, err := estimator.Eval(
    offchainInputs, onchainInputs,
    offchainOutputs, onchainOutputs,
)
```

## Example Programs

### Offchain Input Program Examples

**Free for recoverable inputs:**
```cel
inputType == 'recoverable' ? 0.0 : 200.0
```

**Weighted fee (1% of amount):**
```cel
weight * 0.01 * amount
```

**Time-based fee (free if expires in less than 5 minutes):**
```cel
expiry - now() < double(duration('5m').getSeconds()) ? 0.0 : amount / 2.0
```

### Onchain Input Program Examples

**Fixed fee per boarding input:**
```cel
200.0
```

**Percentage fee (0.1% of amount):**
```cel
amount * 0.001
```

### Output Program Examples

**Fixed fee per output:**
```cel
100.0
```

**Percentage fee:**
```cel
amount * 0.002
```

**Fee based on script type (example using script length):**
```cel
size(script) > 50 ? amount * 0.01 : amount * 0.005
```

## Return Type

All CEL programs must return a `double` (floating-point number) representing the fee amount in satoshis. The result is converted to a `FeeAmount` type, which can be converted to satoshis using `ToSatoshis()`.

