# arkd

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/arkade-os/arkd)](https://github.com/arkade-os/arkd/releases)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Farkade--os%2Farkd-blue?logo=docker)](https://github.com/arkade-os/arkd/pkgs/container/arkd)
[![Integration](https://github.com/arkade-os/arkd/actions/workflows/integration.yaml/badge.svg)](https://github.com/arkade-os/arkd/actions/workflows/integration.yaml)
[![ci_unit](https://github.com/arkade-os/arkd/actions/workflows/unit.yaml/badge.svg)](https://github.com/arkade-os/arkd/actions/workflows/unit.yaml)
[![GitHub](https://img.shields.io/github/license/arkade-os/arkd)](https://github.com/arkade-os/arkd/tree/master/LICENSE)
![Go Reference](https://pkg.go.dev/badge/github.com/arkade-os/arkd.svg)

> **⚠️ IMPORTANT DISCLAIMER: ALPHA SOFTWARE**
> `arkd` is currently in alpha stage. This software is experimental and under active development.
> **DO NOT ATTEMPT TO USE IN PRODUCTION**. Use at your own risk.


## What is arkd?

`arkd` is the server implementation of Arkade instance that builds on top of the Ark protocol, a Bitcoin scaling solution that enables fast, low-cost off-chain transactions while maintaining Bitcoin's security guarantees. As an Arkade Operator, the server:

- Creates and manages Batch Outputs through on-chain Bitcoin transactions
- Facilitates off-chain transactions between users
- Provides liquidity for commitment transactions (on-chain settlements that finalize each batch)

The Operator's role is designed with strict boundaries that ensure users always maintain control over their funds. This architecture allows for efficient transaction batching while preserving the trustless nature of Bitcoin.


## Supported Networks and Wallets

`arkd` supports the following Bitcoin network:
* regtest
* testnet3
* signet
* mutinynet
* mainnet

and uses [lnwallet](https://pkg.go.dev/github.com/lightningnetwork/lnd/lnwallet/btcwallet) as embedded on-chain wallet.

## Usage Documentation

In this documentation, you'll learn how to install and use `arkd`, a Bitcoin server for off-chain Bitcoin transactions.

### Installing from GitHub Releases

1. Download the latest `arkd` binary from the [GitHub Releases page](https://github.com/arkade-os/arkd/releases)

2. Make the binary executable:
   ```sh
   chmod +x arkd
   ```

3. Move the binary to a directory in your PATH (optional):
   ```sh
   sudo mv arkd /usr/local/bin/
   ```

### Configuration Options

The `arkd` server can be configured using environment variables.

| Environment Variable | Description | Default |
|---------------------|-------------|--------|
| `ARKD_DATADIR` | Directory to store data | App data directory |
| `ARKD_PORT` | Port to listen on | `7070` |
| `ARKD_LOG_LEVEL` | Logging level (0-6, where 6 is trace) | `4` (info) |
| `ARKD_ROUND_INTERVAL` | Interval between rounds in seconds | `30` |
| `ARKD_DB_TYPE` | Database type (postgres, sqlite, badger) | `postgres` |
| `ARKD_DB_URL` | Postgres connection url if `ARKD_DB_TYPE` is set to `postgres` | - |
| `ARKD_EVENT_DB_TYPE` | Event database type (redis, inmemory) | `redis` |
| `ARKD_EVENT_DB_URL` | Event database url if `ARKD_EVENT_DB_TYPE` is set to `postgres` | - |
| `ARKD_TX_BUILDER_TYPE` | Transaction builder type (covenantless) | `covenantless` |
| `ARKD_LIVE_STORE_TYPE` | Cache service type (redis, inmemory) | `redis` |
| `ARKD_REDIS_URL` | Redis db connection url if `ARKD_LIVE_STORE_TYPE` is set to `redis` | - |
| `ARKD_REDIS_NUM_OF_RETRIES` | Maximum number of retries for Redis write operations in case of conflicts | - |
| `ARKD_VTXO_TREE_EXPIRY` | VTXO tree expiry in seconds | `604672` (7 days) |
| `ARKD_UNILATERAL_EXIT_DELAY` | Unilateral exit delay in seconds | `86400` (24 hours) |
| `ARKD_BOARDING_EXIT_DELAY` | Boarding exit delay in seconds | `7776000` (3 months) |
| `ARKD_ESPLORA_URL` | Esplora API URL | `https://blockstream.info/api` |
| `ARKD_WALLET_ADDR` | The arkd wallet address to connect to in the form `host:port` | - |
| `ARKD_NO_MACAROONS` | Disable macaroon authentication | `false` |
| `ARKD_NO_TLS` | Disable TLS | `true` |
| `ARKD_UNLOCKER_TYPE` | Wallet unlocker type (env, file) to enable auto-unlock | - |
| `ARKD_UNLOCKER_FILE_PATH` | Path to unlocker file | - |
| `ARKD_UNLOCKER_PASSWORD` | Wallet unlocker password | - |
| `ARKD_ROUND_MAX_PARTICIPANTS_COUNT` | Maximum number of participants per round | `128` |
| `ARKD_ROUND_MIN_PARTICIPANTS_COUNT` | Minimum number of participants per round | `1` |
| `ARKD_UTXO_MAX_AMOUNT` | The maximum allowed amount for boarding or collaborative exit | `-1` (unset) |
| `ARKD_UTXO_MIN_AMOUNT` | The minimum allowed amount for boarding or collaborative exit | `-1` (dust) |
| `ARKD_VTXO_MAX_AMOUNT` | The maximum allowed amount for vtxos | `-1` (unset) |
| `ARKD_VTXO_MIN_AMOUNT` | The minimum allowed amount for vtxos | `-1` (dust) |

## Provisioning

### Data Directory

By default, `arkd` stores all data in the following location:

- Linux: `~/.arkd/`
- macOS: `~/Library/Application Support/arkd/`
- Windows: `%APPDATA%\arkd\`

You can specify a custom data directory using the `ARKD_DATADIR` environment variable.

### Connecting to Bitcoin

#### Option 1: Connect to Bitcoin Core via RPC

To connect `arkd` to your own Bitcoin Core node via RPC, use these environment variables:

```sh
export ARKD_WALLET_BITCOIND_RPC_USER=admin1
export ARKD_WALLET_BITCOIND_RPC_PASS=123
export ARKD_WALLET_BITCOIND_RPC_HOST=localhost:18443
```

For ZMQ notifications (recommended for better performance):

```sh
export ARKD_WALLET_BITCOIND_ZMQ_BLOCK=tcp://localhost:28332
export ARKD_WALLET_BITCOIND_ZMQ_TX=tcp://localhost:28333
```

#### Option 2: Connect via Neutrino

For a lighter setup using Neutrino (BIP 157/158):

```sh
export ARKD_WALLET_NEUTRINO_PEER=yourhost:p2p_port_bitcoin
```

If none of the above options are specified, the wallet uses Neutrino by default with peer discovery.

### Wallet Setup

1. Start the wallet:
   ```sh
   arkd-wallet
   ```

2. Start arkd:
   ```sh
   arkd
   ```

3. Create a new wallet:
   ```sh
   arkd wallet create --password <password>
   ```

   Or restore from mnemonic:
   ```sh
   arkd wallet create --mnemonic "your twelve word mnemonic phrase here" --password <password>
   ```

4. Unlock the wallet:
   ```sh
   arkd wallet unlock --password <password>
   ```

5. Generate a funding address:
   ```sh
   arkd wallet address
   ```

6. Fund the on-chain address with BTC and wait for at least 2 confirmations.

7. Check your wallet balance:
   ```sh
   arkd wallet balance
   ```

8. Withdraw funds from your wallet:
   ```sh
   arkd wallet withdraw --address <address> --amount <amount_in_btc>
   ```

For a complete list of available commands and options:
   ```sh
   arkd --help
   ```

## Repository Structure

- [`api-spec`](./api-spec/): Ark Protocol Buffer API specification.
- [`pkg`](./pkg/): collection of reusable packages and services.
  - [`ark-lib`](./pkg/ark-lib): collection of data structures and functions reusable by arkd and sdk.
  - [`arkd-wallet`](./pkg/arkd-wallet): bitcoin wallet service used as liquidity provider and signer.
  - [`ark-cli`](./pkg/ark-cli): ark offchain and onchain wallet as command line interface.
- [`internal`](./internal): arkd implementation.
  - [`core`](./internal/core): contains the core business logic of arkd.
    - [`application`](./internal/core/application/): contains the implementation of the service responsible for the [core operations](https://github.com/arkade-os/arkd/tree/master/README.md#L19-L22).
    - [`domain`](./internal/core/domain/): models and events managed by the application service.
    - [`ports`](./internal/core/ports/): collection of interfaces of the services used by the application one, like for example the wallet, the cache or the database.
  - [`infrastructure`](./internal/infrastructure/): contains implementations of the interfaces defined in `internal/core/ports`. Every folder contains the different implementations of the same interface.
  - [`interface`](./internal/interface/): contains the implementations of the interface layer of arkd
    - [`grpc`](./internal/interface/grpc/): the gRPC implementation of the arkd interface. All gRPC methods are also mapped to REST endpoints.
- [`test/e2e`](./test/e2e): contains the integration tests.

## Development

### Compile binary from source

To compile the `arkd` binary from source, you can use the following Make commands from the root of the repository:

- `make build`: Builds the `arkd` binary for your platform.
- `make build-all`: Builds the `arkd` binary for all platforms.

### Contributing Guidelines

1. **No force pushing in PRs**: Always use `git push --force-with-lease` to avoid overwriting others' work.
2. **Sign your commits**: Use GPG to sign your commits for verification.
3. **Squash and merge**: When merging PRs, use the "Squash and merge" option to maintain a clean commit history.
4. **Testing**: Add tests for each new major feature or bug fix.
5. **Keep master green**: The master branch should always be in a passing state. All tests must pass before merging.

### Local Development Setup

1. Install Go (version 1.23 or later)
2. Install [Nigiri](https://nigiri.vulpem.com/) for local Bitcoin networks
3. Start Nigiri to setup a regtest Bitcoin environment:

   ```sh
   nigiri start
   ```

4. Clone this repository:

   ```sh
   git clone https://github.com/arkade-os/arkd.git
   cd arkd
   ```

5. Install dependencies:

   ```sh
   go mod download
   ```

6. Run arkd wallet in dev mode:

   ```sh
   # with neutrino
   make run-wallet-neutrino
   # or with bitcoind
   make run-wallet-bitcoind
   ```

7. Run arkd in dev mode:

   ```sh
   # with sqlite db and inmemory cache
   make run-light
   # or with postgres db and redis cache
   make run
   ```

### Testing

1. Lint and format code:

   ```sh
   make lint
   ```

2. Run unit tests:

   ```sh
   make test
   ```

3. Run integration tests ([start nigiri](https://github.com/arkade-os/arkd/tree/master/README.md#L218) if needed first):

   ```sh
   make docker-run
   make integrationtest
   make docker-stop
   ```


In the `envs/` folder you can find the several dev-mode configurations for `arkd` and `arkd-wallet`.

## Support

If you encounter any issues or have questions, please file an issue on our [GitHub Issues](https://github.com/arkade-os/arkd/issues) page.

## Security

We take the security of Ark seriously. If you discover a security vulnerability, we appreciate your responsible disclosure.

Currently, we do not have an official bug bounty program. However, we value the efforts of security researchers and will consider offering appropriate compensation for significant, [responsibly disclosed vulnerabilities](./SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
