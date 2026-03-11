# SDK Version Compatibility

The server enforces minimum SDK version requirements at two levels:

- **Service-level** (global): rejects all calls to a service when the SDK is too
  old. Use this when the server has moved far enough ahead that an old SDK simply
  cannot work with any endpoint in the service.
- **Method-level** (per-RPC): rejects calls to a specific method when the SDK is
  too old. Use this when a specific endpoint has a breaking change but the rest of
  the service still works.

When both levels are set, the tighter (higher) constraint wins.

## How it works

1. Each gRPC **service** can declare a `service_min_sdk_version` option and each
   **method** can declare a `min_sdk_version` option in its proto definition.
2. At startup the server scans all registered proto descriptors and builds maps
   of service and method minimum versions.
3. On every request the server reads the SDK version header. It picks the higher
   of the service-level and method-level minimum, then compares it against the
   client version. If the client version is below the minimum, the request is
   rejected.
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

### Service-level (global minimum)

Annotate the service in its `.proto` file with the custom service option:

```protobuf
import "ark/v1/options.proto";

service ArkService {
  option (ark.v1.service_min_sdk_version) = "1.0.0";
}
```

Every method in `ArkService` will now require SDK >= 1.0.0.

### Method-level (per-RPC)

Annotate individual RPCs with the custom method option:

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
