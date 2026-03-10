# SDK Version Compatibility

The server enforces minimum SDK version requirements on a per-RPC basis. When an
API method introduces a breaking change, the proto definition is annotated with
the minimum SDK version required to call it. Clients running an older SDK receive
a clear error instructing them to upgrade.

## How it works

1. Each gRPC method can declare a `min_sdk_version` option in its proto
   definition.
2. At startup the server scans all registered proto descriptors and builds a map
   of method to minimum version.
3. On every request the server reads the SDK version header and compares it
   against the minimum. If the client version is below the minimum, the request
   is rejected.
4. If client does not pass a header, we do not perform the version comparison,
   allowing for backward compatibility for calls, and the request is not rejected.

### Client header

| Transport | Header |
|-----------|--------|
| gRPC | `x-ark-sdk-version` (metadata key) |
| REST | `X-Ark-Sdk-Version` (HTTP header) |

The value must be a semver string, optionally prefixed with `v` (e.g. `0.9.0` or
`v0.9.0`).

### Decision table

| Condition | Result |
|-----------|--------|
| No header sent | Request allowed |
| Version >= minimum | Request allowed |
| Version < minimum | `SDK_VERSION_TOO_OLD` error |
| Malformed version string | Request allowed |
| Method has no minimum declared | Request allowed |

## Declaring a breaking change

Annotate the RPC in its `.proto` file with the custom method option:

```protobuf
import "ark/v1/options.proto";

service ArkService {
  rpc RegisterIntent(RegisterIntentRequest) returns (RegisterIntentResponse) {
    option (ark.v1.min_sdk_version) = "0.9.0";
  }
}
```

Then regenerate proto stubs:

```bash
make proto
```

The server will automatically pick up the annotation at startup -- no Go code
changes required.

## Error details

When a client is rejected the gRPC status contains:

- **Code**: maps to `SDK_VERSION_TOO_OLD`
- **Message**: human-readable, e.g. `RegisterIntent requires SDK version >= 0.9.0`
- **Metadata fields**:
  - `client_version` -- the version string sent by the client
  - `min_version` -- the minimum version required
  - `method` -- the full gRPC method name (e.g. `/ark.v1.ArkService/RegisterIntent`)
