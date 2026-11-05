# AGENTS.md

arkd is the Arkade operator server. Onchain, it emulates opcodes that Bitcoin lacks, so UTXOs can
be locked by covenants and carry nominal values (assets) through the Arkade assets protocol. The
same features are available offchain via the Ark protocol, with instant transactions and no fees.
Users stay in control of their funds: if the operator goes away, they can unroll their VTXOs
onchain. Offchain funds expire, so users must renew them periodically. Treat signing, forfeit,
sweep and fee code as code that moves money. When your Ark knowledge disagrees with the repo,
trust the code but if you think the code is buggy and conflicts with repo intentions then ask a
human. For terms like VTXO, batch, intent, forfeit or boarding, see the
[Arkade glossary](https://docs.arkadeos.com/learn/glossary).

## Repository layout

```
cmd/                         arkd, arkd-wallet and arkd-signer entry points
api-spec/                    protobuf and OpenAPI specs, generated code in protobuf/gen
internal/core/domain/        models and events, imports nothing else from internal/
internal/core/application/   business logic, imports only domain and ports from internal/, anything
                             else from pkg/ or external deps
internal/core/ports/         interfaces the application uses (wallet, db, signer, cache...)
internal/infrastructure/     implementations of ports, one folder per interface
internal/interface/grpc/     gRPC handlers, also served as REST
internal/test/e2e/           integration tests against a regtest stack
pkg/                         reusable Go modules, each with its own go.mod (ark-lib, client-lib...)
envs/                        env files used by the make run targets
```

## Commands

Build, test, lint and codegen commands are Makefile targets. Run `make help` to list them.
The Development section of `README.md` covers local setup and the e2e flow. For a quick loop run
one test with `go test -run '^TestName$' ./path/to/pkg/`, since most packages need no pg or redis.

## Linting

`make lint` runs golangci-lint with `.golangci.yml`, which enables the default linters plus the
`gofmt`, `goimports` and `golines` formatters. It fixes what it can. CI runs the same check, so
run it before you commit.

- Only the root module is linted. The modules under `pkg/` have their own `go.mod`, so neither
  `make lint` nor CI checks them. Follow the same rules there by hand.
- Test files are skipped (`--tests=false`).
- Lines should cap at 100 chars. Wrap comments, strings and test code yourself.
- Wrap long calls and signatures yourself before running `make lint`. Fill each line up to the
  limit, instead of putting one argument per line as JS formatters do. `golines` also splits
  one argument per line, so don't leave the wrapping to it.

## Code layout

Order a non-test Go file top to bottom like this.

1. Types, interfaces, constants and vars.
2. The factory function (`NewService`, `NewScheduler`...).
3. Exported methods.
4. Unexported methods.
5. Util functions and structs.

`internal/infrastructure/db/service.go` is a good reference.

- Match the style of the file you edit. Don't reformat or rewrite code the change doesn't need.
- Errors that reach clients use a code from `pkg/errors`
  (`Code[Metadata]{number, NAME, grpc code}`). Reuse an existing code when one fits and add a new
  one only when none does. Don't send a bare `fmt.Errorf` through the API. Put details that must
  not reach the client in `WithInternalCause`.
- Return errors. Don't add a `panic` to non-test code.
- Comments concisely explain why the code exists, not what it does. No ticket numbers, PR links or
  change history in comments.
- Never hand-edit generated code in `api-spec/protobuf/gen`, `api-spec/openapi/swagger` or
  `internal/infrastructure/db/postgres/sqlc/queries`. Edit the source and regenerate.

## Unit tests

A `_test.go` file reads top to bottom like this.

1. Package-level vars, constants and types the tests share.
2. The test functions.
3. Helpers and helper structs.

Test packages generally use the `_test` suffix and test only exported functions. Some layers, like
`internal/core/application`, are exceptions.

Inside a test, follow these rules.

- Every `TestXxx` should test exactly one function and `Xxx` should be its name.
- Group cases under `valid` and `invalid` subtests. When possible (most of the time), define
  fixtures as a list of unnamed structs with name, data and expected result or error.
  `TestProcessBoardingInputs` in `internal/core/application/boarding_validation_test.go` is a
  good reference.
- In some cases, like `TestAuthToken` in `internal/core/application/indexer_exposure_test.go`, we
  want to unit test a flow rather than a single function. That test is a good reference since it
  contains "common" valid and invalid subtests but also "custom" ones that are specific edge cases
  of the flow that can't be really generalized.
- Use `testify/require`. Reuse an existing mock before you write a new one.
- Always use `t.Context()` as context. Use `context.Background()` only in rare, specific cases.
- Use `t.Cleanup` instead of `defer`. Use `defer` only in rare, specific cases.
- A bug fix ships with a test that fails without the fix and passes with it.
- Don't write tests that only restate the implementation. Delete test files that cover nothing new.
- Only report test results you actually ran.
- The db package tests drop and recreate their schemas. Run them through `make test`, which gives
  them a throwaway postgres.

## Making a change

- Never assume. Check a claim against the code before you make it.
- Before you add a file, read two neighbours in the same folder and copy their structure. A new
  port implementation should look like the existing ones under `internal/infrastructure/`.
- Read every caller of a function before you change it. Fix a bug in the shared code every caller
  uses, not only in the caller the issue mentions.
- Keep the diff to the task. Unrelated fixes go in their own PR.
- Don't add, remove or upgrade dependencies unless the task needs it.
- Fix the cause of a lint or test failure. Don't disable the linter or weaken the test.
- Protobuf changes must not break clients. Read `api-spec/BREAKING_CHANGES.md` and run
  `./scripts/check-proto-breaking`.
- Create db migrations with `make FILE=<name> migrate`, so both `up.sql` and `down.sql` exist.
- Read `docs/settings.md` before changing settings and `docs/version-compat.md` before changing
  version gating.

## Commits and PRs

- Before you commit, run the tests of the packages you touched. Run `go mod tidy` in any module
  whose `go.mod` you changed.
- CI fails on a `go mod tidy` diff. It also runs lint, gosec at high severity, `make test` and
  `make test-pkg`.
- Sign every commit.
- Keep the commit subject to one short sentence. Recent history uses prefixes like `Fix:` or
  `[sweeper]` when they help.
- Push with `--force-with-lease`, never `--force`.
- PRs are squash merged into `master`, and `master` must stay green.
- You cannot work directly on `master`.
