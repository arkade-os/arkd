# Settings: first-boot seeding and runtime management

`arkd` keeps its operational settings (exit delays, amount limits, round participants, fees, 
scheduled session, …) in a **single row in the database**. That row is the source of truth at runtime.

This document explains where those settings come from, and — importantly — when the `ARKD_*`
environment variables matter and when they are ignored.

## TL;DR

- **First boot only:** the settings row is seeded from the `ARKD_*` environment variables listed
below (or their defaults if unset).
- **Every boot after that:** those environment variables are **ignored**. The stored row wins.
Changing, say, `ARKD_VTXO_MIN_AMOUNT` after the first start has **no effect**.
- To change a setting after the first boot, use the **admin API** 
(see [Changing settings after first boot](#changing-settings-after-first-boot)).

## Lifecycle

```
                    ┌─────────────────────────────────────────────┐
   first boot  ──►  │ settings row is empty                       │
                    │   → seed it from ARKD_* env vars / defaults  │
                    │   → carry over any legacy fees/session rows  │
                    └─────────────────────────────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────────┐
  later boots  ──►  │ settings row already exists                 │
                    │   → seed is skipped entirely                 │
                    │   → ARKD_* settings env vars are ignored     │
                    └─────────────────────────────────────────────┘
                                      │
                                      ▼
                    change settings at runtime via the admin API
```

The seed runs exactly once, gated on the settings table being empty.
It never re-runs and never overwrites a value an admin changed later.

> **Note:** only the *settings* environment variables below follow this first-boot-only rule.
> Infrastructure variables (database, wallet/signer addresses, ports, TLS, unlocker, …) are read 
> on **every** boot as usual.

## Seed environment variables

All variables use the `ARKD_` prefix. The values shown are the defaults applied when the variable
is unset on first boot.

| Environment variable                     | Setting                          | Unit / notes                                                        | Default     |
|------------------------------------------|----------------------------------|---------------------------------------------------------------------|-------------|
| `ARKD_SESSION_DURATION`                  | `session_duration`               | seconds                                                             | `30`        |
| `ARKD_UNROLLED_VTXO_MIN_EXPIRY_MARGIN`   | `unrolled_vtxo_min_expiry_margin`| seconds                                                             | `300`       |
| `ARKD_BAN_THRESHOLD`                     | `ban_threshold`                  | number of crimes to trigger a ban (`0` disables banning)            | `3`         |
| `ARKD_BAN_DURATION`                      | `ban_duration`                   | seconds                                                             | `300`       |
| `ARKD_VTXO_TREE_EXPIRY`                  | `vtxo_tree_expiry`               | relative locktime (≥ 512 = seconds, < 512 = blocks)                 | `604672`    |
| `ARKD_UNILATERAL_EXIT_DELAY`             | `unilateral_exit_delay`          | relative locktime (≥ 512 = seconds, < 512 = blocks)                 | `86400`     |
| `ARKD_PUBLIC_UNILATERAL_EXIT_DELAY`      | `public_unilateral_exit_delay`   | relative locktime (≥ 512 = seconds, < 512 = blocks)                 | `86400`     |
| `ARKD_CHECKPOINT_EXIT_DELAY`             | `checkpoint_exit_delay`          | relative locktime (≥ 512 = seconds, < 512 = blocks)                 | `86400`     |
| `ARKD_BOARDING_EXIT_DELAY`               | `boarding_exit_delay`            | relative locktime (≥ 512 = seconds, < 512 = blocks)                 | `7776000`   |
| `ARKD_ROUND_MIN_PARTICIPANTS_COUNT`      | `round_min_participants_count`   | count                                                               | `1`         |
| `ARKD_ROUND_MAX_PARTICIPANTS_COUNT`      | `round_max_participants_count`   | count                                                               | `128`       |
| `ARKD_VTXO_MIN_AMOUNT`                   | `vtxo_min_amount`                | sats (`-1` = native dust limit)                                     | `-1`        |
| `ARKD_VTXO_MAX_AMOUNT`                   | `vtxo_max_amount`                | sats (`-1` = no limit)                                              | `-1`        |
| `ARKD_UTXO_MIN_AMOUNT`                   | `utxo_min_amount`                | sats (`-1` = native dust limit)                                     | `-1`        |
| `ARKD_UTXO_MAX_AMOUNT`                   | `utxo_max_amount`                | sats (`-1` = no limit, `0` = boarding disabled)                     | `-1`        |
| `ARKD_SETTLEMENT_MIN_EXPIRY_GAP`         | `settlement_min_expiry_gap`      | seconds (`0` = disabled)                                            | `0`         |
| `ARKD_VTXO_NO_CSV_VALIDATION_CUTOFF_DATE`| `vtxo_no_csv_validation_cutoff_date` | unix timestamp (`0` = disabled)                                 | `0`         |
| `ARKD_MAX_TX_WEIGHT`                     | `max_tx_weight`                  | weight units                                                        | `40000`     |
| `ARKD_MAX_OP_RETURN_OUTS`                | `max_op_return_outputs`          | count (floored to a minimum of `1`)                                 | `3`         |
| `ARKD_ASSET_TX_MAX_WEIGHT_RATIO`         | `asset_tx_max_weight_ratio`      | ratio in the open interval `(0, 1)`                                 | `0.5`       |
| `ARKD_NOTE_URI_PREFIX`                   | `note_uri_prefix`                | string                                                              | `""`        |
| `ARKD_MIN_BUILD_VERSION_HEADER`          | `build_version_header`           | min accepted client build version, semver (e.g. `v2.3.4`); empty = no minimum | `""`        |
| `ARKD_MIN_BUILD_VERSION_HEADER_REQUIRED` | `build_version_header_required`  | bool; if `true`, clients must send a valid `X-Build-Version` header (requires `build_version_header`) | `false`     |
| `ARKD_DIGEST_HEADER_REQUIRED`            | `digest_header_required`         | bool; if `true`, clients must send a matching `X-Digest` header     | `false`     |

### Notes on specific values

- **Exit delays / tree expiry** are relative locktimes: a value of `512` or greater is interpreted
as **seconds**, a smaller value as a number of **blocks**. Block-based locktimes are only allowed
on `regtest`; on other networks the value must be expressed in seconds.
- **`vtxo_min_amount` / `utxo_min_amount` = `-1`** means "use the wallet's native dust limit".
The *effective* minimum applied at runtime is the larger of the configured value and the dust
limit; this resolution happens at boot and lives only in the in-memory cache — it is **not** 
written back to the stored settings row, so the persisted value stays as configured 
(`-1` by default).
- **`utxo_max_amount = 0`** disables boarding / collaborative exit entirely 
(a `-1` means "no limit").

### Client compatibility headers

Three settings gate which clients the public `ArkService` accepts. They are enforced by gRPC
interceptors on every `ArkService` call:

- **`build_version_header`** is the minimum server build version clients must advertise
(semver, e.g. `v2.3.4`). A client advertises the build version via the `X-Build-Version` header;
if it is *below* this minimum the request is rejected. Leave empty to not enforce a minimum.
- **`build_version_header_required`** controls what happens when a client sends **no** (or an
unparseable) `X-Build-Version` header: when `true` such requests are rejected; when `false` a 
missing header is allowed (a header that *is* present is always validated against the minimum). 
When this is `true`, `build_version_header` must be set — otherwise settings validation fails.
- **`digest_header_required`**: when `true`, clients must send an `X-Digest` header matching the
server's configuration digest (which `GetInfo` advertises). The digest changes whenever any config
parameter change, so a stale client is rejected and must refresh. `GetInfo` is **exempt** from this
check, so a client can always (re)learn the current digest.

All three can be changed at runtime via the admin API like any other setting; the matching `arkd`
CLI flags are `--build-version-header`, `--build-version-header-required` and 
`--digest-header-required`.

## Changing settings after first boot

Once seeded, settings are managed exclusively through the admin API.
Changes are applied as **partial updates**: only the fields you send are modified, the rest are 
left unchanged.

| Endpoint                              | Method | Description                                   |
|---------------------------------------|--------|-----------------------------------------------|
| `/v1/admin/settings`                  | GET    | Retrieve current settings                     |
| `/v1/admin/settings`                  | POST   | Update settings (partial; only provided fields change) |
| `/v1/admin/scheduledSession`          | GET    | Retrieve the scheduled session config         |
| `/v1/admin/scheduledSession`          | POST   | Update the scheduled session config           |
| `/v1/admin/scheduledSession/clear`    | POST   | Clear the scheduled session config            |
| `/v1/admin/intentFees`                | GET    | Retrieve the batch (intent) fee config        |
| `/v1/admin/intentFees`                | POST   | Update the batch (intent) fee config          |
| `/v1/admin/intentFees/clear`          | POST   | Clear the batch (intent) fee config           |

## Provisioning convenience

For local/dev setups, the settings variables above are set in 
[`docker-compose.regtest.yml`](../docker-compose.regtest.yml).
Remember they only take effect on the **first** start against a fresh database; to re-seed from env 
vars you would need to start against an empty `settings` table 
(e.g. a fresh data directory / database).

## Legacy migration

If you are upgrading from a build that stored fees in the `intent_fees` table or scheduled sessions
in the `scheduled_session` table, their latest values are carried over into the unified settings
row during the first-boot seed, so no configuration is lost. 
Those legacy tables are then emptied and will be dropped in a future release.
