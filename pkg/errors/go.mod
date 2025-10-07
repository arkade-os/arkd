module github.com/arkade-os/arkd/pkg/errors

replace github.com/arkade-os/arkd/api-spec => ../../api-spec

replace github.com/arkade-os/arkd/pkg/ark-lib => ../ark-lib

go 1.24.6

require (
	github.com/arkade-os/arkd/api-spec v0.0.0-00010101000000-000000000000
	github.com/arkade-os/arkd/pkg/ark-lib v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.76.0
)

require (
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/protobuf v1.36.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
