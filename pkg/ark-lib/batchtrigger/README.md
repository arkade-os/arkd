# batchtrigger

The `batchtrigger` package compiles and evaluates an operator-supplied
[CEL](https://github.com/google/cel-spec) formula that decides whether the
server should start a new batch round. It mirrors the design of
[`pkg/ark-lib/arkfee`](../arkfee/README.md) — programs are compiled once and
reused on every evaluation.

## When the gate runs

The compiled program is evaluated at the top of `startRound()`, before any
new round state is created. If it returns `true`, the round proceeds as
before. If it returns `false`, the server logs a debug message, waits one
sixth of `ARKD_SESSION_DURATION` (the same cadence as the registration
window), and re-checks.

A nil/empty program is permissive: the gate always allows the round, which
preserves the legacy "start every session" behaviour for deployments that do
not configure `ARKD_BATCH_TRIGGER`.

## CEL Environment

A program must return `bool`. The following variables are exposed:

| Variable | Type | Description |
|----------|------|-------------|
| `intents_count` | `double` | Number of pending intents queued |
| `current_feerate` | `double` | Current mempool fee rate in sat/kvbyte (as reported by the wallet) |
| `time_since_last_batch` | `double` | Seconds elapsed since the last finalized batch (`0` if no batch finalized since boot) |
| `boarding_inputs_count` | `double` | Total number of pending boarding UTXOs across all queued intents |
| `total_boarding_amount` | `double` | Total satoshis across all pending boarding UTXOs |
| `total_intent_fees` | `double` | Total implicit fees in satoshis across all pending intents (sum of `(input amounts) - (output amounts)` per intent) |

The `now() -> double` helper is also available and returns the current Unix
timestamp in seconds.

## Examples

All variables are typed as `double`, so numeric literals must use the `.0`
form (e.g. `1.0`, not `1`). CEL is strictly typed and will refuse `>` between
a `double` and an `int`.

**Original example from the issue — only batch when there's more than one
intent and either fees are low or an hour has passed:**

```cel
intents_count > 1.0 && (current_feerate <= 2.0 || time_since_last_batch >= 3600.0)
```

**Pure boarding-driven settlement (settle whenever a non-trivial amount of
sats is queued in boarding):**

```cel
boarding_inputs_count > 0.0 && total_boarding_amount >= 100000.0
```

**Combined revenue and time gate (settle when at least 500 sats of intent
fees are on the table or it's been more than 30 minutes):**

```cel
total_intent_fees >= 500.0 || time_since_last_batch >= 1800.0
```

**Always-on (default behaviour when `ARKD_BATCH_TRIGGER` is unset):**

```cel
true
```

## Validation

The program is compiled once at server startup. Any of the following errors
are surfaced before the server begins serving traffic:

* CEL syntax errors
* a return type other than `bool`
* references to variables that are not in the table above
* type mismatches in operators or function calls

This means a misconfigured program never makes it past `arkd Validate()`.
