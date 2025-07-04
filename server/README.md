# Ark Server

**ALPHA STAGE SOFTWARE: USE AT YOUR OWN RISK!**

## Development

### Prerequisites

- [Go](https://go.dev/doc/install)
- [Bitcoin Core](https://bitcoincore.org) with `compact block filters` enabled

### Run in dev mode

1. Run arkd-wallet
```bash
cd pkg/ark-wallet
make run-neutrino
```

2. Run arkd with postgres db and redis cache
```bash
cd server
make run
```

3. Or, run arkd with sqlite db and inmemory cache
```bash
cd server
make run-light
```

Refer to [config.go](./internal/config/config.go) for the available configuration options via ENV VARs.

### Test

Always lint before testing:
```bash
make lint
```

Run the unit tests with:
```bash
make test
```

To run the integration tests, first go to the root fodler and start up a test env:
```bash
make docker-run
```
Then, run the integration tests with:
```bash
make integrationtest
```

### CLI commands

* `arkd` - runs the ark server
* `arkd wallet`
  *  `create` - initializes or restores the server's wallet
  *  `unlock` - unlocks the wallet
  *  `address` - derives a receiving address
  *  `balance` - returns the wallet balance
  *  `withdraw` - sends funds to some given destination
* `arkd note` - generates ark notes with the given amount
* `arkd intents` - view or manage the queue of registered intents
* `arkd scheduled-sweeps` - returns info about the scheduled sweeping of batch outputs
* `arkd round-info` - returns details on a specific round
* `arkd market-hour` - view or manage the market hour configuration

Run `ark <cmd> --help` to get info about the required and optional flags for any command.
