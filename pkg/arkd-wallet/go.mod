module github.com/arkade-os/arkd/pkg/arkd-wallet

go 1.26.6

replace github.com/btcsuite/btcd/btcec/v2 => github.com/btcsuite/btcd/btcec/v2 v2.5.0

replace github.com/arkade-os/arkd/pkg/ark-lib => ../ark-lib

replace github.com/arkade-os/arkd/api-spec => ../../api-spec

require (
	github.com/arkade-os/arkd/api-spec v0.0.0-00010101000000-000000000000
	github.com/arkade-os/arkd/pkg/ark-lib v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/address/v2 v2.0.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btcd/btcutil/v2 v2.0.1
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0
	github.com/btcsuite/btcd/psbt/v2 v2.0.0
	github.com/btcsuite/btcd/txscript/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.1
	github.com/dgraph-io/badger/v4 v4.8.0
	github.com/google/uuid v1.6.0
	github.com/grafana/pyroscope-go v1.2.7
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/lightningnetwork/lnd v0.21.0-beta.rc2.0.20260828055859-d24719e0a3d3
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/viper v1.20.1
	github.com/timshannon/badgerhold/v4 v4.0.3
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.54.0
	go.opentelemetry.io/otel v1.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.14.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.40.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.40.0
	go.opentelemetry.io/otel/log v0.14.0
	go.opentelemetry.io/otel/metric v1.44.0
	go.opentelemetry.io/otel/sdk v1.44.0
	go.opentelemetry.io/otel/sdk/log v0.14.0
	go.opentelemetry.io/otel/sdk/metric v1.44.0
	golang.org/x/net v0.56.0
	google.golang.org/grpc v1.83.1
)

require (
	github.com/btcsuite/btcd/v2transport v1.1.0 // indirect
	github.com/btcsuite/btclog/v2 v2.0.1-0.20250728225537-6090e87c6c5b // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/grafana/pyroscope-go/godeltaprof v0.1.9 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.7 // indirect
	github.com/jackc/pgconn v1.14.3 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	github.com/lightningnetwork/lnd/fn/v2 v2.0.9 // indirect
	github.com/onsi/ginkgo v1.16.4 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btcd v0.26.2 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/btcsuite/btcwallet v0.18.0
	github.com/btcsuite/btcwallet/wallet/txauthor v1.4.0 // indirect
	github.com/btcsuite/btcwallet/wallet/txrules v1.3.0 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.3.0 // indirect
	github.com/btcsuite/btcwallet/walletdb v1.6.0 // indirect
	github.com/btcsuite/btcwallet/wtxmgr v1.6.0 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/btcsuite/winsvc v1.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/decred/dcrd/lru v1.1.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fergusstrange/embedded-postgres v1.28.0 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/golang-migrate/migrate/v4 v4.17.1 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/gorilla/websocket v1.5.3
	github.com/jessevdk/go-flags v1.6.1 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/jrick/logrotate v1.1.2 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/neutrino v0.18.0 // indirect
	github.com/lightninglabs/neutrino/cache v1.1.4 // indirect
	github.com/lightningnetwork/lnd/clock v1.1.1 // indirect
	github.com/lightningnetwork/lnd/queue v1.2.0 // indirect
	github.com/lightningnetwork/lnd/ticker v1.1.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.4.0 // indirect
	github.com/ltcsuite/ltcd v0.23.5 // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0
	github.com/miekg/dns v1.1.61 // indirect
	github.com/ory/dockertest/v3 v3.11.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.11.1
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/xiang90/probing v0.0.0-20221125231312-a49e3df8f510 // indirect
	go.etcd.io/etcd/api/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/v3 v3.5.15 // indirect
	go.etcd.io/etcd/server/v3 v3.5.15 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.40.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.40.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/crypto v0.53.0
	golang.org/x/exp v0.0.0-20250811191247-51f88131bc50 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/term v0.44.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240801135723-a856999a2e4a // indirect
	modernc.org/libc v1.59.3 // indirect
	modernc.org/sqlite v1.33.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
