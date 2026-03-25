# SDK Version Compatibility

The server enforces a minimum SDK major version globally, derived from its own
build version. Any client whose major version is below the server's major
version is rejected.

Only the **major** version component is compared. Minor and patch versions are
ignored. For example, if the server is built as `v2.3.1`, a client at `2.0.0`,
`2.1.0`, or `2.99.0` all pass, but `1.9.9` is rejected.

## How it works

1. At build time the server version is set via `-ldflags` (see
   `scripts/build-arkd`).
2. On startup the server parses the major version from its build version string.
3. On every request the server reads the client's SDK version header, extracts
   the major version, and compares it against its own. If the client's major
   version is lower, the request is rejected.
4. If a client does not send a header, the version check is skipped, allowing
   backward compatibility.

### Client header

| Transport | Header |
|-----------|--------|
| gRPC | `x-ark-sdk-version` (metadata key) |
| REST | `X-Ark-Sdk-Version` (HTTP header) |

The value must be a semver string, optionally prefixed with `v` (e.g. `1.0.0` or
`v1.0.0`). Only the major version component is used for comparison.

### Decision table

| Condition | Result |
|-----------|--------|
| No header sent | Request allowed |
| Major version >= server major | Request allowed |
| Major version < server major | `SDK_VERSION_TOO_OLD` error |
| Malformed version string | Request allowed |

## Future: method-level versioning

A planned enhancement is to support per-method (per-RPC) version constraints,
allowing individual endpoints to declare their own minimum SDK version
independently of the global server version. This would enable finer-grained
control when a specific RPC introduces a breaking change but the rest of the
service remains compatible with older clients. This has not been implemented yet.

## Error details

When a client is rejected the gRPC status contains:

- **Code**: maps to `SDK_VERSION_TOO_OLD`
- **Message**: human-readable, e.g. `server requires SDK major version >= 2`
- **Metadata fields**:
  - `client_version` -- the version string sent by the client
  - `min_version` -- the server's build version
