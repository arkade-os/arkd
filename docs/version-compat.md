# Build Version Compatibility

The server enforces a minimum build version globally, derived from its own build
version. Any client below that version is rejected.

The full `major.minor.patch` triple is compared, in that order. If the server is
built as `v2.3.1` then `2.3.1` and `2.4.0` pass, but `2.3.0`, `2.2.9` and `1.9.9`
are all rejected. Pre-release and build suffixes on the patch component are
ignored, so `1.2.3-rc1` is treated as patch `3`.

## How it works

1. At build time the server version is set via `-ldflags` (see
   `scripts/build-arkd`).
2. On startup the server parses its own build version string.
3. On every request the server reads the client's SDK version header and compares
   it against its own, major first, then minor, then patch. If the client is
   lower, the request is rejected.
4. If a client does not send a header, the version check is skipped, allowing
   backward compatibility — unless `build_version_header_required` is set, in
   which case a missing or unparseable header is rejected.

### Client header

| Transport | Header |
|-----------|--------|
| gRPC | `x-build-version` (metadata key) |
| REST | `X-Build-Version` (HTTP header) |

The value must be a semver string, optionally prefixed with `v` (e.g. `1.0.0` or
`v1.0.0`). Missing components default to zero, so `1` is read as `1.0.0`.

### Decision table

| Condition | Result |
|-----------|--------|
| No header sent | Allowed, unless `build_version_header_required` is set |
| Malformed version string | Allowed, unless `build_version_header_required` is set |
| Version >= server version | Request allowed |
| Version < server version | `BUILD_VERSION_TOO_OLD` error |

Two things worth knowing:

- The guard applies only to the public `ArkService`. Admin and indexer RPCs are
  never gated.
- If the server's own build version cannot be parsed — a local or unreleased
  build with no `-ldflags` — the guard is disabled for every client.

## Future: method-level versioning

A planned enhancement is to support per-method (per-RPC) version constraints,
allowing individual endpoints to declare their own minimum build version
independently of the global server version. This would enable finer-grained
control when a specific RPC introduces a breaking change but the rest of the
service remains compatible with older clients. This has not been implemented yet.

## Error details

When a client is rejected the gRPC status contains:

- **Code**: maps to `BUILD_VERSION_TOO_OLD`
- **Message**: human-readable, e.g. `server requires build version header >= 2`
- **Metadata fields**:
  - `client_version` -- the version string sent by the client
  - `min_version` -- the server's build version
