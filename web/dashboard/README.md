# arkd console

A read-only operator console for arkd. Static HTML, CSS, and ES modules — no
framework, no bundler, no dependencies, no build step. The sources are the
artifact.

## What it does

Every read the `arkd` CLI can do, in a browser, with the solvency arithmetic
already worked out.

| Panel | Covers |
|---|---|
| Overview | Liability by expiry bucket, coverage against the wallet balance, fee rate, wallet state |
| Batches | Batch list with what each unswept batch still holds and when it becomes reclaimable (joined from the sweep schedule), fail reasons, and drill-down into details and intents |
| Scheduled sweeps | Batches not yet reclaimed: when each becomes sweepable and how much comes back |
| Offchain txs | Ark tx list with fail reasons, drill-down into checkpoints |
| Intent queue | Intents waiting for the next batch, with their decoded intent message and a PSBT proof inspector |
| Convictions | Search by time range, batch, script, or id |
| Config | Settings and scheduled-session configuration |
| Fees | The intent fee CEL programs and fees collected over a window |
| Wallet | Balance and the main-account UTXO set |
| VTXO lookup | Indexer search by script or outpoint, with chain and commitment drill-down |

### What it deliberately cannot do

The client issues **GET requests only**. There is no code path that can send
another method, so the console cannot withdraw, sweep, create notes, unlock or
restore a wallet, load a signer key, change settings, ban or pardon a script, or
delete queued intents. Use the CLI for those.

Two endpoints are GETs but are still excluded, because they are not reads:
`/v1/admin/wallet/seed` generates key material, and `/v1/admin/wallet/address`
advances the wallet's derivation index.

## The Overview panel

`arkd liquidity-report` prints five numbers. This panel shows those five plus
three things the CLI cannot tell you:

- **The overdue bucket.** VTXOs past `expires_at` that were never swept fall out
  of both halves of the report — the expiring query needs `expires_at > after`,
  and the recoverable query needs `swept = true`. They are real liability that
  the CLI reports nowhere. The console finds them by querying `after=1`
  (`after=0` gets coerced to *now* by the handler).
- **Coverage.** Total liability against the wallet balance that has to back it.
- **Derived totals.** Reclaimable-within-72h, locked-in-batches, and the total.

Known accounting caveats, restated in the panel itself: notes count as
liability even though the operator minted them, and `recoverable` does not
exclude unrolled VTXOs while the expiring buckets do.

## Configuration

Three environment variables, read at container start:

| Variable | Required | Example |
|---|---|---|
| `ARKD_ADMIN_URL` | yes | `https://arkd.internal:7071` |
| `ARKD_INDEXER_URL` | no | `https://arkd.internal:7070` |
| `ARKD_EXPLORER_URL` | no, defaults to `https://arkade.space` | `https://mempool.space/signet` |

`ARKD_EXPLORER_URL` is a block explorer base: every txid in the console carries
an out-link to `<explorer>/tx/<txid>`. It defaults to the mainnet explorer,
`https://arkade.space`, so set it on signet or regtest or the links point at the
wrong chain. It is only ever a link target, so it is not added to `connect-src`.

The indexer lives on arkd's **public** gateway, not the admin one, so when
`ARKD_ADMIN_PORT` is set these are different URLs. Leave `ARKD_INDEXER_URL`
empty and the VTXO lookup and commitment drill-downs hide themselves.

`entrypoint.sh` renders `config.js` and the CSP `connect-src` from these on
every start, so restarting with changed values picks them up.

## Running it

```sh
make console
make console-stop
```

Defaults point at a local arkd (`http://localhost:7071` admin,
`http://localhost:7070` indexer) on port 8080. Override any of them:

```sh
make console \
  CONSOLE_ADMIN_URL=https://arkd.internal:7071 \
  CONSOLE_INDEXER_URL=https://arkd.internal:7070 \
  CONSOLE_EXPLORER_URL=https://mempool.space/signet \
  CONSOLE_PORT=9000
```

Set `CONSOLE_INDEXER_URL=` (empty) to run without the indexer panels. Re-running
`make console` replaces the existing container, so it is safe to repeat.

Then open the printed URL and paste the **read-only** macaroon as hex:

```sh
xxd -p -c 1000 <datadir>/macaroons/readonly.macaroon
```

If arkd runs with `--no-macaroons` (the regtest compose stack does), the console
detects that on load and connects with no credential at all.

These URLs are dialled by **your browser**, not by another container, so they
have to be reachable from your machine — `localhost:7071`, not `arkd:7071`.

Under the hood that is just:

```sh
docker build -t arkd-console web/dashboard
docker run --rm -p 8080:80 \
  -e ARKD_ADMIN_URL=https://arkd.internal:7071 \
  -e ARKD_INDEXER_URL=https://arkd.internal:7070 \
  arkd-console
```

### Without Docker

Any static host works. Render into a scratch directory rather than in place —
the rendering step rewrites `index.html`, and you want the placeholder version
to survive in the repo:

```sh
OUT=$(mktemp -d)
cp web/dashboard/*.html web/dashboard/*.css web/dashboard/*.js \
   web/dashboard/config.js.tpl "$OUT/"

ROOT="$OUT" \
ARKD_ADMIN_URL=https://arkd.internal:7071 \
ARKD_INDEXER_URL=https://arkd.internal:7070 \
  sh -c 'set -e; . web/dashboard/entrypoint.sh' || true   # the trailing nginx exec fails; ignore it

python3 -m http.server -d "$OUT" 8080
```

The `|| true` is there because `entrypoint.sh` ends by exec'ing nginx, which is
not installed locally. Everything before that — both template renders — runs
normally.

## Which macaroon

`readonly.macaroon`. Every endpoint the console calls needs only `manager:read`
and `wallet:read`, which is exactly what `ReadOnlyPermissions()` grants, so that
credential is sufficient and nothing stronger should be used.

That matters because a client-side GET-only restriction is not a security
boundary on its own: anyone holding the credential can call arkd directly.
`readonly.macaroon` makes the restriction real. It cannot withdraw, sweep, mint
notes, unlock the wallet, derive an address, change settings, ban or pardon a
script, delete intents, or revoke tokens.

Both halves of that are enforced by tests in
`internal/interface/grpc/permissions/console_test.go`: one asserts every console
RPC is satisfied by the read-only macaroon, the other asserts the read-only
macaroon does *not* authorise the dangerous surface. Adding a panel that needs a
write op fails the build.

Servers started with `--no-macaroons` need no credential; the console probes for
that on load and skips the connect screen. The probe deliberately calls
`GetSettings` rather than `wallet/status`, because the latter is whitelisted and
answers without a macaroon even on an authenticated server.

## Security

- **The macaroon is never persisted.** It lives in a module closure in
  `api.js`, and is never written to `localStorage`, `sessionStorage`, cookies,
  or the URL. It is dropped on reload, on the Lock button, and after 15 minutes
  idle.
- **CSP pins the reachable origins.** `connect-src` is rendered to exactly the
  configured admin and indexer URLs, so a compromised page cannot post the
  macaroon to a third party. `default-src 'none'`, no inline scripts, no
  external requests of any kind.
- **No `innerHTML` anywhere.** All API values land in `textContent`, so a
  hostile fail reason or script hex can never become markup.
- **CORS needs nothing.** arkd's gateway already sends `Access-Control-Allow-Origin: *`
  on both routers, so no proxy and no arkd change is required.

## Large servers

Two things keep big deployments usable:

- **Listing is one query.** `GetRounds` used to load every round in the window
  individually to build the list. Filtering, ordering and the limit now happen
  in SQL, backed by an index on `round(starting_timestamp)`. Over 800 rounds
  that is 2.3 s and ~2400 queries before, 2.4 ms and one query after.
- **Tables cap themselves at 500 rows.** A batch can hold tens of thousands of
  leaf VTXOs, and building that much DOM blocks the main thread long enough to
  look hung. Tables render the first 500 and offer an explicit "Render all"
  (20 000 rows renders in ~2 s when asked for).

The indexer paginates server-side already (300 tree nodes, 500 forfeit txs per
page), so those panels show the first page.

A macaroon in a browser tab is still a macaroon in a browser tab. Serve this
over TLS on a trusted network, not the public internet.

## Layout

```
index.html      shell, connect gate, CSP
app.js          hash router, nav, lock, idle clock
api.js          the only module that talks to arkd; GET-only, holds the macaroon
table.js        generic descriptor -> table/definition renderer
panels.js       descriptors for the ~20 straightforward endpoints
solvency.js     Overview: liability buckets, coverage
batch.js        batch detail and its intents
offchainTx.js   offchain tx detail
indexer.js      commitment and VTXO drill-downs
psbt.js         BIP-174 decoder and its modal; runs offline in the tab
fmt.js          amounts, timestamps, hashes, badges, DOM helper
style.css       one stylesheet, tokens in :root
```

Adding a straightforward endpoint means adding a descriptor to `panels.js` and a
route to `ROUTES` in `app.js`.
