# arkfee

The `arkfee` package provides fee estimation for Ark intents using CEL (Common Expression Language) expressions. It allows you to define custom fee calculation logic for both input and output operations.

CEL language definition:
https://github.com/google/cel-spec/blob/master/doc/langdef.md#list-of-standard-definitions

## Overview

The package provides an `Estimator` that can evaluate CEL expressions to calculate fees based on input and output characteristics. Each estimator can have two separate programs:
- **Intent Input Program**: Evaluated for each input in an intent
- **Intent Output Program**: Evaluated for each output in an intent

The total fee is the sum of all input fees plus all output fees.

## CEL Environments

The package provides two CEL environments, each with their own set of available variables and functions.

### IntentInputEnv

Used for evaluating input fee calculations. Available variables:

| Variable | Type | Description |
|----------|------|-------------|
| `amount` | `double` | Amount in satoshis |
| `expiry` | `double` | Expiry date in Unix timestamp seconds (only available if input has an expiry) |
| `birth` | `double` | Birth date in Unix timestamp seconds (only available if input has a birth time) |
| `weight` | `double` | Weighted liquidity lockup ratio of a vtxo |
| `inputType` | `string` | Type of the input: `'vtxo'`, `'boarding'`, `'recoverable'`, or `'note'` |

### IntentOutputEnv

Used for evaluating output fee calculations. Available variables:

| Variable | Type | Description |
|----------|------|-------------|
| `amount` | `double` | Amount in satoshis |
| `outputType` | `string` | Type of the output: `'vtxo'` or `'onchain'` |

## Available Functions

Both environments provide the following functions:

### `now() -> double`

Returns the current Unix timestamp in seconds.

**Example:**
```cel
expiry - now() < double(duration('5m').getSeconds()) ? 0.0 : amount / 2.0
```

## Usage

### Creating an Estimator

```go
estimator, err := arkfee.New(intentInputProgram, intentOutputProgram)
if err != nil {
    // handle error
}
```

Both programs are optional. If a program is empty, the corresponding fee evaluation will return 0.

### Evaluating Fees

```go
// Evaluate fee for a single input
inputFee, err := estimator.EvalInput(arkfee.Input{
    Amount: 10000,
    Expiry: time.Now().Add(time.Hour),
    Birth:  time.Now().Add(-10 * time.Minute),
    Type:   arkfee.InputTypeVtxo,
    Weight: 1.0,
})

// Evaluate fee for a single output
outputFee, err := estimator.EvalOutput(arkfee.Output{
    Amount: 5000,
    Type:   arkfee.OutputTypeOnchain,
})

// Evaluate total fee for multiple inputs and outputs
totalFee, err := estimator.Eval(inputs, outputs)
```

## Example Programs

### Input Program Examples

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

### Output Program Examples

**Free for vtxo outputs:**
```cel
outputType == 'vtxo' ? 0.0 : 200.0
```

**Percentage fee for onchain outputs:**
```cel
outputType == 'onchain' ? amount * 0.2 : 0.0
```

## Return Type

All CEL programs must return a `double` (floating-point number) representing the fee amount in satoshis. The result is converted to a `FeeAmount` type, which can be converted to satoshis using `ToSatoshis()`.

