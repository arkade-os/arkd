module github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer

go 1.24.6

replace github.com/btcsuite/btcd/btcec/v2 => github.com/btcsuite/btcd/btcec/v2 v2.3.3

replace github.com/arkade-os/arkd/pkg/ark-lib => ../ark-lib

replace github.com/arkade-os/arkd/api-spec => ../../api-spec

require (
	github.com/arkade-os/arkd/api-spec v0.0.0-00010101000000-000000000000
	github.com/arkade-os/arkd/pkg/ark-lib v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/dgraph-io/badger/v4 v4.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.2
	github.com/lightningnetwork/lnd v0.18.2-beta
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/viper v1.20.1
	github.com/timshannon/badgerhold/v4 v4.0.3
	golang.org/x/net v0.43.0
	google.golang.org/grpc v1.75.0
	google.golang.org/protobuf v1.36.8
)

require (
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/onsi/ginkgo v1.16.4 // indirect
)

require (
	dario.cat/mergo v1.0.1 // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/btcwallet v0.16.10-0.20240718224643-db3a4a2543bd
	github.com/btcsuite/btcwallet/wallet/txauthor v1.3.4 // indirect
	github.com/btcsuite/btcwallet/wallet/txrules v1.2.1 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.2.4 // indirect
	github.com/btcsuite/btcwallet/walletdb v1.4.2 // indirect
	github.com/btcsuite/btcwallet/wtxmgr v1.5.3 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/btcsuite/winsvc v1.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/decred/dcrd/lru v1.1.3 // indirect
	github.com/docker/cli v27.1.1+incompatible // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fergusstrange/embedded-postgres v1.28.0 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang-migrate/migrate/v4 v4.17.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/gorilla/websocket v1.5.3
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgtype v1.14.3 // indirect
	github.com/jackc/pgx/v4 v4.18.3 // indirect
	github.com/jackc/pgx/v5 v5.6.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jessevdk/go-flags v1.6.1 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/jrick/logrotate v1.0.0 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/neutrino v0.16.1-0.20240425105051-602843d34ffd // indirect
	github.com/lightninglabs/neutrino/cache v1.1.2 // indirect
	github.com/lightningnetwork/lightning-onion v1.2.1-0.20240712235311-98bd56499dfb // indirect
	github.com/lightningnetwork/lnd/clock v1.1.1 // indirect
	github.com/lightningnetwork/lnd/fn v1.2.1 // indirect
	github.com/lightningnetwork/lnd/healthcheck v1.2.5 // indirect
	github.com/lightningnetwork/lnd/kvdb v1.4.10 // indirect
	github.com/lightningnetwork/lnd/queue v1.1.1 // indirect
	github.com/lightningnetwork/lnd/sqldb v1.0.3 // indirect
	github.com/lightningnetwork/lnd/ticker v1.1.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.2.6 // indirect
	github.com/lightningnetwork/lnd/tor v1.1.3 // indirect
	github.com/ltcsuite/ltcd v0.23.5 // indirect
	github.com/miekg/dns v1.1.61 // indirect
	github.com/opencontainers/runc v1.2.4 // indirect
	github.com/ory/dockertest/v3 v3.11.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.20.2 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.10.0
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/xiang90/probing v0.0.0-20221125231312-a49e3df8f510 // indirect
	go.etcd.io/etcd/api/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/v3 v3.5.15 // indirect
	go.etcd.io/etcd/server/v3 v3.5.15 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.28.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.opentelemetry.io/proto/otlp v1.5.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/crypto v0.41.0
	golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/term v0.34.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240801135723-a856999a2e4a // indirect
	modernc.org/libc v1.59.3 // indirect
	modernc.org/sqlite v1.33.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
