# Explorer Demo Examples

This directory contains example programs demonstrating the multi-connection explorer functionality.

## Multi-Connection Demo

The `multi_connection_demo.go` demonstrates the explorer's ability to handle high-volume address subscriptions using multiple WebSocket connections.

### Usage

```bash
go run example/multi_connection_demo/multi_connection_demo.go [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-addresses` | int | 1500 | Number of addresses to generate and subscribe |
| `-listenners` | int | 1 | Number of listeners watching for events |
| `-url` | string | https://mempool.space/api | Explorer API URL |
| `-max-events` | int | 5 | Maximum events to receive before stopping (0 = unlimited) |
| `-show-all` | bool | false | Show all subscribed addresses (not just first 3) |

#### Understanding subscriptions

Because of Mempool limitations, every address needs to be tracked with a dedicated WebSocket connection.

When started, the explorer creates a new WS connection to make sure it can be established and keeps it open for the very first addresses that will be subscribed.

Since the limit of opened connections can vary based on server (Mempool) configuration and the host where the explorer client runs, when an address is subscribed, the service tries to open a new connection for the next address to subscribe. If that fails, it won't accept other addresses to subscribe unless one or many are unsubscribed.

When one or many addresses are unsubscribed, the connections are kept open for newer addresses to subscribe. Connections are closed only when the service is stopped. 

### Examples

#### Default Configuration (1500 addresses)
```bash
go run example/multi_connection_demo/multi_connection_demo.go
```

#### Stress Test: 500 addresses on single connection
```bash
go run example/multi_connection_demo/multi_connection_demo.go --addresses 500
```

#### Listen for events with many clients 
```bash
go run example/multi_connection_demo/multi_connection_demo.go --listeners 50
```

#### Listen indefinitely for events
```bash
go run example/multi_connection_demo/multi_connection_demo.go --max-events 0
```

### Verification Features

The demo verifies the actual runtime configuration from the explorer service:
- **Connection Count**: Actual number of active WebSocket connections
- **Explorer Configuration**: Confirmed batch size and delay settings
- **Subscription Count**: Real-time count of subscribed addresses
- **Fallback Detection**: Automatically detects when polling mode is active

## Alice to Bob Example

The `alice_to_bob/` directory contains a complete example of sending Bitcoin transactions using the Ark protocol.

```bash
go run example/alice_to_bob/alice_to_bob.go
```

This example demonstrates:
- Setting up Ark clients
- Onboarding funds
- Sending off-chain transactions
- Settling transactions
