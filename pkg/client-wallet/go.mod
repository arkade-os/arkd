module github.com/arkade-os/arkd/pkg/client-wallet

replace github.com/arkade-os/arkd/pkg/client-lib => ../client-lib

replace github.com/arkade-os/arkd/pkg/ark-lib => ../ark-lib

replace github.com/arkade-os/arkd/api-spec => ../../api-spec

replace github.com/arkade-os/arkd/pkg/errors => ../errors

replace github.com/btcsuite/btcd/btcec/v2 => github.com/btcsuite/btcd/btcec/v2 v2.3.3

go 1.26.3

require (
	github.com/arkade-os/arkd/pkg/ark-lib v0.0.0-00010101000000-000000000000
	github.com/arkade-os/arkd/pkg/client-lib v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/lightningnetwork/lnd v0.18.2-beta
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.48.0
)

require (
	cel.dev/expr v0.25.1 // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/arkade-os/arkd/api-spec v0.0.0-00010101000000-000000000000 // indirect
	github.com/arkade-os/arkd/pkg/errors v0.0.0-00010101000000-000000000000 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/btcwallet v0.16.10-0.20240718224643-db3a4a2543bd // indirect
	github.com/btcsuite/btcwallet/wallet/txauthor v1.3.4 // indirect
	github.com/btcsuite/btcwallet/wallet/txrules v1.2.1 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.2.4 // indirect
	github.com/btcsuite/btcwallet/walletdb v1.4.2 // indirect
	github.com/btcsuite/btcwallet/wtxmgr v1.5.3 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/decred/dcrd/lru v1.1.2 // indirect
	github.com/google/cel-go v0.26.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/neutrino v0.16.1-0.20240425105051-602843d34ffd // indirect
	github.com/lightninglabs/neutrino/cache v1.1.2 // indirect
	github.com/lightningnetwork/lnd/clock v1.1.1 // indirect
	github.com/lightningnetwork/lnd/fn v1.2.1 // indirect
	github.com/lightningnetwork/lnd/queue v1.1.1 // indirect
	github.com/lightningnetwork/lnd/ticker v1.1.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.2.6 // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/term v0.40.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto v0.0.0-20240812133136-8ffd90a71988 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
