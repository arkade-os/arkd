package livestore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	redislivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/redis"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/stretchr/testify/require"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
)

var (
	connectorsJSON = `[{"Tx":"cHNidP8BAOwDAAAAAcXuArkhSrxO59ox0sKDFr0zZzeJuIImgzIGH5oiKx63AQAAAAD/////BU0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhFNAQAAAAAAACJRIIuBxfGXLJBxAcCzUNERqM25pggGv/bwyR8wuLMXmQ4RTQEAAAAAAAAiUSCLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEU0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAAAAAA==","Children":{"0":"5e1eae3436fa3175eb238b3cc22cfccd17ec32c8f6cfd911e03f58f83b05fd7b","1":"8c8c00c0b0966880a8e9dacd8e266f3ddf938e817c7bd40295bddc5e45d900ea","2":"584408db5ed86cd5c51e2f6f027fa40a6584c3c91b8103d45ae36bc55d8a7329","3":"cbeecbaa2cd83534762c7720b29ad8e4fd9bca7e6d1a26a41a2fe0f48ef7bd6f"},"Txid":"b4f79f5c8b27c6fb08ffe57c3eabdd4d77d6cd21e099bee890877949ac3b3c21"},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AAAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{},"Txid":"5e1eae3436fa3175eb238b3cc22cfccd17ec32c8f6cfd911e03f58f83b05fd7b"},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AQAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{},"Txid":"8c8c00c0b0966880a8e9dacd8e266f3ddf938e817c7bd40295bddc5e45d900ea"},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AgAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{},"Txid":"584408db5ed86cd5c51e2f6f027fa40a6584c3c91b8103d45ae36bc55d8a7329"},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AwAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{},"Txid":"cbeecbaa2cd83534762c7720b29ad8e4fd9bca7e6d1a26a41a2fe0f48ef7bd6f"}]`
	intentsJSON    = `[{"Id":"d4d1735d-05d1-493c-ac3a-b0bb634a50fe","Inputs":[{"Txid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","VOut":0,"Amount":5000,"PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpiresAt":253402300799,"Preconfirmed": true,"CreatedAt":1749818677},{"Txid":"c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198","VOut":1,"Amount":99997000,"PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpiresAt":253402300799,"Preconfirmed":true,"CreatedAt":1749818677}],"Receivers":[{"Amount":100002000,"OnchainAddress":"","PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24"}]},{"Id":"6eef6c69-179c-4fe8-b183-e79637838255","Inputs":[{"Txid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","VOut":1,"Amount":99995000,"PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpiresAt":253402300799,"Preconfirmed":true,"CreatedAt":1749818677},{"Txid":"c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198","VOut":0,"Amount":3000,"PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpiresAt":253402300799,"Preconfirmed":true,"CreatedAt":1749818677}],"Receivers":[{"Amount":99998000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}]`
	tx1            = "cHNidP8BAIgDAAAAAnv9BTv4WD/gEdnP9sgy7BfN/CzCPIsj63Ux+jY0rh5eAAAAAAD/////q7i/0+MBfAFLRcdx3UBTTlCHIFJ4B3hpDUU0e/lL53kAAAAAAP////8C1RQAAAAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEriBMAAAAAAAAiUSBwhtcqjdrMnm4EUdkhM+9YPWdIpHJrYyqU8m34yAKsJEEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUAMWsyNnOkGuXqv1tZryHrR2opcv1IE8y8vd0plIWjcBzC75lIIeMaV3QLOicJkpx854Hpb4hdGylSRnw9wTDBjQhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDAx+14WC2NF93SA39AJr+zuMBDbBkzxBXNHpuv/6Dnb0UgLyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1StIDaW50nxJTR9gvLAoXOmCm76EX2uxlTKpPeMF5TI/Q8jrMAAAAA="
	tx2            = "cHNidP8BAIgDAAAAAm+994704C8apCYabX7Km/3k2JqyIHcsdjQ12Cyqy+7LAAAAAAD/////mNHiF2WGWq/0gRn7RfOw496tjW4WB99qKuyVHa4XrsQBAAAAAP////8Cldb1BQAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQErSNX1BQAAAAAiUSBwhtcqjdrMnm4EUdkhM+9YPWdIpHJrYyqU8m34yAKsJEEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUASzdEkMZS1M3JBzp2N/ky+nki8GRJ5WpQY/7UZLI8AuFe0+26NmFuwbCdABpfu0vbRcwgKOS+9B3Fot0jlBLP5QhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDAx+14WC2NF93SA39AJr+zuMBDbBkzxBXNHpuv/6Dnb0UgLyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1StIDaW50nxJTR9gvLAoXOmCm76EX2uxlTKpPeMF5TI/Q8jrMAAAAA="
	tx3            = "cHNidP8BAIgDAAAAAuoA2UVe3L2VAtR7fIGOk989byaOzdrpqIBolrDAAIyMAAAAAAD/////q7i/0+MBfAFLRcdx3UBTTlCHIFJ4B3hpDUU0e/lL53kBAAAAAP////8Cxc71BQAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEreM31BQAAAAAiUSB1lMms2ZbM9mdDF2m7SyOLKantMrc/ORhcEhz3cKoKY0EU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDpuqwgR4YEuiemShPyiNdDm0AX1aj0sm1E5JUWApXGIahSpPpWhImz2GlO+PMJHdVNXEKXoDePj91v6H6PK1a0QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQInUzArzkE6X+bP/eCF7F1PzaedGuM4wtX5roc9fOZ1Ja0XTErh5GUWMdZUGaqIDBlbggnPZjidgCFpV1DlEry5CFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSAvKuLNrWCJPsc8XESpsjpK3f6Fm6rxdU/hk9on8x6nVK0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIC8q4s2tYIk+xzxcRKmyOkrd/oWbqvF1T+GT2ifzHqdUrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAA="
	tx4            = "cHNidP8BAIgDAAAAAilzil3Fa+Na1AOBG8nDhGUKpH8Cby8exdVs2F7bCERYAAAAAAD/////mNHiF2WGWq/0gRn7RfOw496tjW4WB99qKuyVHa4XrsQAAAAAAP////8CBQ0AAAAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEruAsAAAAAAAAiUSB1lMms2ZbM9mdDF2m7SyOLKantMrc/"

	intentFixture1 = `{"boardingInputs":[{"Txid":"1e1448b9f2c44e4bc861db45864097d94fa7519dab9cba12c886a0c244932145","VOut":1,"Tapscripts":["039d0440b27520fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4eac","20fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4ead203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67"],"intent":{"Id":"0222bfa8-c753-4b41-a5f9-d4e12d726413","Inputs":[{"Txid":"24de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10da","VOut":0,"RootCommitmentTxid":"0000000000000000000000000000000000000000000000000000000000000000","CommitmentTxids":["0000000000000000000000000000000000000000000000000000000000000000"]}],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}}`
	intentFixture2 = `{"boardingInputs":[{"Txid":"14de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10db","VOut":1,"Tapscripts":["039d0440b275202f2ae2cdad60893ec73c5c44a9b23a4addfe859baaf1754fe193da27f31ea754ac","202f2ae2cdad60893ec73c5c44a9b23a4addfe859baaf1754fe193da27f31ea754ad203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096"],"intent":{"Id":"2a4d69f3-ce1b-40b3-a48d-fb61ec21b15f","Inputs":[],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24"}]}}`
	intentFixture3 = `{"boardingInputs":[{"Txid":"1e1448b9f2c44e4bc861db45864097d94fa7519dab9cba12c886a0c244932145","VOut":1,"Tapscripts":["039d0440b27520fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4eac","20fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4ead203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67"],"intent":{"Id":"aaaaaaaa-c753-4b41-a5f9-d4e12d726413","Inputs":[{"Txid":"24de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10da","VOut":0,"RootCommitmentTxid":"0000000000000000000000000000000000000000000000000000000000000000","CommitmentTxids":["0000000000000000000000000000000000000000000000000000000000000000"]}],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}}`

	offchainTxJSON = `{"Stage":{"Code":2,"Ended":false,"Failed":false},"StartingTimestamp":1749818677,"EndingTimestamp":0,"ArkTxid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","ArkTx":"cHNidP8BAJYDAAAAAeB4gUdsoDHu7o2F4IkLICEbEt0y9MejPi5mWzdZtxBBAAAAAAD/////A4gTAAAAAAAAIlEgcIbXKo3azJ5uBFHZITPvWD1nSKRya2MqlPJt+MgCrCR4zfUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjAAAAAAAAAAAEUQJOcwAAAAAAAQErAOH1BQAAAAAiUSDTwlo9WBKfqLWlkkznHmITfQzQEU37+YWWyqn5B2dyGEEU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDpuqwgR4YEuiemShPyiNdDm0AX1aj0sm1E5JUWApXGIahSpPpWhImz2GlO+PMJHdVNXEKXoDePj91v6H6PK1a0QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQInUzArzkE6X+bP/eCF7F1PzaedGuM4wtX5roc9fOZ1Ja0XTErh5GUWMdZUGaqIDBlbggnPZjidgCFpV1DlEry5CFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAAA","CheckpointTxs":{"4110b759375b662e3ea3c7f432dd121b21200b89e0858deeee31a06c478178e0":"cHNidP8BAGsDAAAAARrFJ/P3vwEZY75OHSqgWMz3RaeIrDt7pxWqEAXZwfz+AAAAAAD/////AgDh9QUAAAAAIlEg08JaPVgSn6i1pZJM5x5iE30M0BFN+/mFlsqp+QdnchgAAAAAAAAAAARRAk5zAAAAAAABASsA4fUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjQRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQCgwEdt3LF/ub7J1hnF3+kbMvbo0Wqt3VpGDsto8wiqy6KL6zHMxKYEZAn1z3SLCo7wKZFsWk1gdx65rINE5JM5CFcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wHYMhmDVZUYnxrCdnty+DMhKJTmw60ZDqTPzCAavjN5ERSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUg+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk6sAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAA="},"CommitmentTxids":{"4110b759375b662e3ea3c7f432dd121b21200b89e0858deeee31a06c478178e0":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"},"RootCommitmentTxId":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","ExpiryTimestamp":199,"FailReason":"","Version":0}`

	intentId1 = "fdbc502adf42a40dc7c0b2d3b50b9c0b01f9c386dc9bef5233bc9f39acdf48ae"
	intentId2 = "340f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff"
	intentId3 = "550f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff"
	intentId4 = "660f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff"
	intentId5 = "770f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff"
	h1        = sha256.Sum256([]byte(intentId1))
	h2        = sha256.Sum256([]byte(intentId2))
	h3        = sha256.Sum256([]byte(intentId3))
	h4        = sha256.Sum256([]byte(intentId4))
	h5        = sha256.Sum256([]byte(intentId5))

	uniqueSignersJSON = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":{},"039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":{},"037f2214791b94cd517ccd561e739ebb73cecacdc41b387beb460dda197c2b7c67":{}}`

	n1 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"025232ea8243113a0cf3a70369f1ca785da06302268a9cab7d20864faf2b892b03234f9f4155bc2d8c4ee7c7e0989dc7a4a4d3a680f352ed05d1091188647c46c101","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"0379d69fa1c63ae8cf9026420fca3fc2728d20fcae5597bfeca6c63884feadcbb4028eb4eaa685ca3ee6fdbd949374a98a505c5c0774f8d410ece28c11572396819d"}`
	n2 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"03489a9e200420f9ae1bb96731cf6d4ecdaa694d816abbbdaa671ac4786f9e79c6403f9361c16a0ad701eb0ee814d9d52928acb1624f38c3b3e89fa35acdb8c6e490","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"03707efe23bc97f17969a5d18c0ddf7223f38dab4b043dbe56a8a9e5b5dc709be3022627414c8c036aafc683ba00a3435b11fb6bda5b4a582e271c7deadfafe0abda"}`
	n3 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"03489a9e200420f9ae1bb96731cf6d4ecdaa694d816abbbdaa671ac4786f9e79c6403f9361c16a0ad701eb0ee814d9d52928acb1624f38c3b3e89fa35acdb8c6e490","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"03707efe23bc97f17969a5d18c0ddf7223f38dab4b043dbe56a8a9e5b5dc709be3022627414c8c036aafc683ba00a3435b11fb6bda5b4a582e271c7deadfafe0abda"}`

	s1 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"74df3c018f86c004e9ecc6bbfe58a958753579f5a5feb3a8ed8dc5c9d4dba5c2","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"2cf641ff3a26702fc0a01bc9fb500b6ca9e79bfd88a31f0569c4767203a75707"}`
	s2 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"c1d480aff75d86460a6f8864782222d05d39b83e4c413c76280e52a09922fe15","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"89c6cbcab945d54f345513338278734c66f94d38016dc1c9842c8a7a2e32d829"}`
	s3 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"c1d480aff75d86460a6f8864782222d05d39b83e4c413c76280e52a09922fe15","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"89c6cbcab945d54f345513338278734c66f94d38016dc1c9842c8a7a2e32d829"}`
)

// testRoundId names the batch a test Pops for, so DeleteVtxos releases the
// inputs that same batch took.
const testRoundId = "test-round"

func TestLiveStoreImplementations(t *testing.T) {
	redisOpts, err := redis.ParseURL("redis://localhost:6379/14")
	require.NoError(t, err)
	rdb := redis.NewClient(redisOpts)
	t.Cleanup(func() { _ = rdb.Close() })
	require.NoError(t, rdb.FlushDB(t.Context()).Err())

	connectors, intents, err := parseForfeitTxsFixture(connectorsJSON, intentsJSON)
	require.NoError(t, err)
	leaves := connectors.Leaves()
	submissions := map[string]struct{ vtxo, connector domain.Outpoint }{
		tx1: {intents[0].Inputs[0].Outpoint, domain.Outpoint{Txid: leaves[0].Txid}},
		tx2: {intents[0].Inputs[1].Outpoint, domain.Outpoint{Txid: leaves[1].Txid}},
		tx3: {intents[1].Inputs[0].Outpoint, domain.Outpoint{Txid: leaves[2].Txid}},
		tx4: {intents[1].Inputs[1].Outpoint, domain.Outpoint{Txid: leaves[3].Txid}},
	}
	txBuilder := &mockedTxBuilder{verify: func(txs []string) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
		valid := make(map[domain.Outpoint]ports.ValidForfeitTx)
		for _, tx := range txs {
			submission, ok := submissions[tx]
			if !ok {
				return nil, fmt.Errorf("unknown forfeit fixture")
			}
			valid[submission.vtxo] = ports.ValidForfeitTx{Tx: tx, Connector: submission.connector}
		}
		return valid, nil
	}}
	store := redislivestore.NewLiveStore(rdb, txBuilder, 5)

	stores := []struct {
		name  string
		store ports.LiveStore
	}{
		{"redis", store},
	}

	for _, tt := range stores {
		t.Run(tt.name, func(t *testing.T) {
			runLiveStoreTests(t, tt.store)
		})
	}
}

func runLiveStoreTests(t *testing.T, store ports.LiveStore) {
	t.Run("IntentStore", func(t *testing.T) {
		ctx := t.Context()

		t.Run("lifecycle", func(t *testing.T) {
			intent1, err := parseIntentFixtures(intentFixture1)
			require.NoError(t, err)
			intent2, err := parseIntentFixtures(intentFixture2)
			require.NoError(t, err)
			intent3, err := parseIntentFixtures(intentFixture3)
			require.NoError(t, err)

			// Push
			err = store.Intents().Push(
				ctx, intent1.Intent, intent1.BoardingInputs, intent1.CosignersPublicKeys,
			)
			require.NoError(t, err)

			err = store.Intents().Push(
				ctx, intent1.Intent, intent1.BoardingInputs, intent1.CosignersPublicKeys,
			)
			require.Contains(t, err.Error(), "duplicated intent")

			err = store.Intents().Push(
				ctx, intent3.Intent, intent3.BoardingInputs, intent3.CosignersPublicKeys,
			)
			require.Contains(t, err.Error(), "duplicated input")

			err = store.Intents().Push(
				ctx, intent2.Intent, intent2.BoardingInputs, intent2.CosignersPublicKeys,
			)
			require.NoError(t, err)

			// try to push an intent with the same boarding input but different Id
			intent2DuplicateBoarding := intent2.Intent
			intent2DuplicateBoarding.Id = uuid.New().String()
			err = store.Intents().Push(
				ctx, intent2DuplicateBoarding, intent2.BoardingInputs, intent2.CosignersPublicKeys,
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "duplicated input")

			// ViewAll
			all, err := store.Intents().ViewAll(
				ctx, []string{intent1.Intent.Id, intent2.Intent.Id, "nonexistent"},
			)
			require.NoError(t, err)
			foundIds := map[string]bool{intent1.Intent.Id: false, intent2.Intent.Id: false}
			for _, r := range all {
				foundIds[r.Id] = true
			}
			for id := range foundIds {
				require.True(t, foundIds[id])
			}

			// IncludesAny
			found, err := store.Intents().IncludesAny(ctx, []domain.Outpoint{})
			require.NoError(t, err)
			require.Empty(t, found)

			existingOutpoints := []domain.Outpoint{
				intent2.BoardingInputs[0].Outpoint,
				intent1.Intent.Inputs[0].Outpoint,
			}
			found, err = store.Intents().IncludesAny(ctx, existingOutpoints)
			require.NoError(t, err)
			require.Equal(t, existingOutpoints, found)

			// Len
			ln, err := store.Intents().Len(ctx)
			require.NoError(t, err)
			require.EqualValues(t, 2, ln)

			// GetSelectedIntents before any pop - should return empty
			selectedIntents, err := store.Intents().GetSelectedIntents(ctx)
			require.NoError(t, err)
			require.Empty(t, selectedIntents)

			// Pop
			selected, err := store.Intents().Pop(ctx, 2, testRoundId)
			require.NoError(t, err)
			require.Len(t, selected, 2)

			// GetSelectedIntents - should return the same intents that were selected
			selectedIntents, err = store.Intents().GetSelectedIntents(ctx)
			require.NoError(t, err)
			require.Len(t, selectedIntents, 2)
			intentsEqual(t, selected, selectedIntents)

			ln, err = store.Intents().Len(ctx)
			require.NoError(t, err)
			require.Zero(t, ln)

			selected, err = store.Intents().Pop(ctx, 100, testRoundId)
			require.NoError(t, err)
			require.Empty(t, selected)

			// GetSelectedIntents after empty pop - should return empty
			selectedIntents, err = store.Intents().GetSelectedIntents(ctx)
			require.NoError(t, err)
			require.Empty(t, selectedIntents)

			// Delete
			err = store.Intents().Delete(ctx, []string{intent1.Intent.Id})
			require.NoError(t, err)

			// Delete non-existent
			err = store.Intents().Delete(ctx, []string{"doesnotexist"})
			require.NoError(t, err)

			// DeleteAll
			err = store.Intents().DeleteAll(ctx)
			require.NoError(t, err)

			// Make sure DeleteVtxos doesn't panic
			err = store.Intents().DeleteVtxos(ctx, testRoundId)
			require.NoError(t, err)
		})

		// At most one intent may hold an input. Pop takes an intent out of the
		// queue but leaves its inputs held, so only an explicit release frees
		// them, and only the intent already holding an input may push it again.
		t.Run("input ownership", func(t *testing.T) {
			// pushArgs is the Push a case asserts on, once arrange has driven
			// the store into the state under test.
			type pushArgs struct {
				intent   domain.Intent
				boarding []ports.BoardingInput
			}

			reset := func(t *testing.T) {
				t.Helper()
				// Pop parks what it selected under its own key and only
				// DeleteAll clears that, so every case has to hand the store
				// back as it found it. Cleanup runs after t.Context is
				// canceled, hence its own ctx.
				t.Cleanup(func() {
					require.NoError(t, store.Intents().DeleteAll(context.Background()))
				})
			}
			push := func(t *testing.T, ctx context.Context, inputs ...domain.Vtxo) domain.Intent {
				t.Helper()
				intent := intentWith(inputs...)
				require.NoError(t, store.Intents().Push(ctx, intent, nil, nil))
				return intent
			}
			popOne := func(t *testing.T, ctx context.Context) ports.TimedIntent {
				t.Helper()
				popped, err := store.Intents().Pop(ctx, 1, testRoundId)
				require.NoError(t, err)
				require.Len(t, popped, 1)
				return popped[0]
			}
			held := func(t *testing.T, ctx context.Context, outpoint domain.Outpoint) bool {
				t.Helper()
				found, _ := store.Intents().IncludesAny(ctx, []domain.Outpoint{outpoint})
				return len(found) > 0
			}

			t.Run("Push", func(t *testing.T) {
				t.Run("valid", func(t *testing.T) {
					tests := []struct {
						name    string
						arrange func(t *testing.T, ctx context.Context) pushArgs
					}{
						{
							name: "an input no intent holds",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								return pushArgs{intent: intentWith(vtxoInput())}
							},
						},
						{
							// Only a different intent is refused, so the holder
							// can be pushed back exactly as Pop returned it.
							name: "an input the same intent already holds",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								push(t, ctx, vtxoInput())
								popped := popOne(t, ctx)
								return pushArgs{
									intent: popped.Intent, boarding: popped.BoardingInputs,
								}
							},
						},
						{
							name: "an input DeleteVtxos released",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								vtxo := vtxoInput()
								push(t, ctx, vtxo)
								popOne(t, ctx)
								require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))
								require.False(t, held(t, ctx, vtxo.Outpoint))
								return pushArgs{intent: intentWith(vtxo)}
							},
						},
					}

					for _, tt := range tests {
						t.Run(tt.name, func(t *testing.T) {
							ctx := t.Context()
							reset(t)

							args := tt.arrange(t, ctx)
							require.NoError(
								t, store.Intents().Push(ctx, args.intent, args.boarding, nil),
							)
						})
					}
				})

				t.Run("invalid", func(t *testing.T) {
					tests := []struct {
						name        string
						arrange     func(t *testing.T, ctx context.Context) pushArgs
						errContains string
					}{
						{
							name: "an input another queued intent holds",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								vtxo := vtxoInput()
								push(t, ctx, vtxo)
								return pushArgs{intent: intentWith(vtxo)}
							},
							errContains: "duplicated input",
						},
						{
							name: "an input another popped intent holds",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								vtxo := vtxoInput()
								push(t, ctx, vtxo)
								popOne(t, ctx)
								require.True(
									t, held(t, ctx, vtxo.Outpoint),
									"Pop must leave the input held",
								)
								return pushArgs{intent: intentWith(vtxo)}
							},
							errContains: "duplicated input",
						},
						{
							name: "an input another intent holds after being pushed again",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								vtxo := vtxoInput()
								push(t, ctx, vtxo)
								popped := popOne(t, ctx)
								require.NoError(t, store.Intents().Push(
									ctx, popped.Intent, popped.BoardingInputs,
									popped.CosignersPublicKeys,
								))
								return pushArgs{intent: intentWith(vtxo)}
							},
							errContains: "duplicated input",
						},
						{
							// Pop lists the inputs it took for the next
							// release. Pushing the holder again takes them off
							// that list, so DeleteVtxos has to leave them held.
							name: "an input another intent still holds after DeleteVtxos",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								vtxo := vtxoInput()
								push(t, ctx, vtxo)
								popped := popOne(t, ctx)
								require.NoError(t, store.Intents().Push(
									ctx, popped.Intent, popped.BoardingInputs,
									popped.CosignersPublicKeys,
								))
								require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))
								require.True(
									t, held(t, ctx, vtxo.Outpoint),
									"pushing the holder again must keep the input held",
								)
								return pushArgs{intent: intentWith(vtxo)}
							},
							errContains: "duplicated input",
						},
						{
							// Boarding inputs are held like vtxo inputs, they
							// just reach Push through their own argument.
							name: "a boarding input another popped intent holds",
							arrange: func(t *testing.T, ctx context.Context) pushArgs {
								boarding := boardingInputs()
								require.NoError(
									t, store.Intents().Push(ctx, boardingIntent(), boarding, nil),
								)
								popOne(t, ctx)
								return pushArgs{intent: boardingIntent(), boarding: boarding}
							},
							errContains: "duplicated input",
						},
					}

					for _, tt := range tests {
						t.Run(tt.name, func(t *testing.T) {
							ctx := t.Context()
							reset(t)

							args := tt.arrange(t, ctx)
							err := store.Intents().Push(ctx, args.intent, args.boarding, nil)
							require.Error(t, err)
							if tt.errContains != "" {
								require.Contains(t, err.Error(), tt.errContains)
							}
						})
					}
				})
			})

			t.Run("concurrent pushes resolved to a single one", func(t *testing.T) {
				ctx := t.Context()
				reset(t)
				const racers = 6

				vtxo := vtxoInput()
				intents := make([]domain.Intent, racers)
				for i := range intents {
					intents[i] = intentWith(vtxo)
				}

				var wg sync.WaitGroup
				errs := make([]error, racers)
				start := make(chan struct{})
				for i := range racers {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						<-start
						errs[i] = store.Intents().Push(ctx, intents[i], nil, nil)
					}(i)
				}
				close(start)
				wg.Wait()

				winners := make([]string, 0, 1)
				for i, err := range errs {
					if err == nil {
						winners = append(winners, intents[i].Id)
						continue
					}
					require.Contains(
						t, err.Error(), "duplicated input",
						"a loser must be turned away for the input, not for something else",
					)
				}
				require.Len(t, winners, 1, "only one push should be accepted")
			})

			// Delete is the other release: it frees the inputs of the intents
			// it removes, both kinds of them.
			t.Run("Delete releases vtxo and boarding inputs", func(t *testing.T) {
				ctx := t.Context()
				reset(t)

				vtxo := vtxoInput()
				boarding := boardingInputs()
				intent := intentWith(vtxo)
				require.NoError(t, store.Intents().Push(ctx, intent, boarding, nil))
				require.NoError(t, store.Intents().Delete(ctx, []string{intent.Id}))

				require.False(t, held(t, ctx, vtxo.Outpoint), "the vtxo input is free again")
				require.NoError(
					t, store.Intents().Push(ctx, intentWith(vtxo), boarding, nil),
					"another intent can hold both",
				)
			})

			// Push and DeleteVtxos decide separately which inputs they touch,
			// so they can disagree on a kind and leave one held for good. A
			// note is an input like any other to both.
			t.Run("DeleteVtxos releases notes like any other input", func(t *testing.T) {
				ctx := t.Context()
				reset(t)

				vtxo, noteVtxo := vtxoInput(), issueNoteVtxo(t, 10_000)
				push(t, ctx, vtxo, noteVtxo)
				popOne(t, ctx)

				for _, outpoint := range []domain.Outpoint{vtxo.Outpoint, noteVtxo.Outpoint} {
					require.True(
						t, held(t, ctx, outpoint), "%s is not held after Pop", outpoint,
					)
				}

				require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))

				stillHeld, key := store.Intents().IncludesAny(
					ctx, []domain.Outpoint{vtxo.Outpoint, noteVtxo.Outpoint},
				)
				require.Empty(t, stillHeld, "%s is still held after DeleteVtxos", key)

				require.NoError(
					t, store.Intents().Push(ctx, intentWith(vtxo, noteVtxo), nil, nil),
					"every released input can be pushed again",
				)
			})
		})
	})

	t.Run("IntentStore vtxo guard set", func(t *testing.T) {
		ctx := t.Context()

		vtxo := domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				VOut: 0,
			},
			Amount:          1000,
			PubKey:          "7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24",
			CommitmentTxids: []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		}
		outpoints := []domain.Outpoint{vtxo.Outpoint}

		pushIntent := func() error {
			intent := domain.Intent{
				Id:        uuid.New().String(),
				Inputs:    []domain.Vtxo{vtxo},
				Receivers: []domain.Receiver{{Amount: 1000, PubKey: vtxo.PubKey}},
			}
			return store.Intents().Push(ctx, intent, nil, nil)
		}

		t.Run("Pop then DeleteVtxos drains the guard set", func(t *testing.T) {
			require.NoError(t, pushIntent())

			found, _ := store.Intents().IncludesAny(ctx, outpoints)
			require.NotEmpty(t, found)

			popped, err := store.Intents().Pop(ctx, 1, testRoundId)
			require.NoError(t, err)
			require.Len(t, popped, 1)

			// the vtxo stays guarded while the round is in flight
			found, _ = store.Intents().IncludesAny(ctx, outpoints)
			require.NotEmpty(t, found)

			require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))

			found, _ = store.Intents().IncludesAny(ctx, outpoints)
			require.Empty(t, found)
		})

		t.Run("re-pushed popped intent keeps the guard", func(t *testing.T) {
			require.NoError(t, pushIntent())

			popped, err := store.Intents().Pop(ctx, 1, testRoundId)
			require.NoError(t, err)
			require.Len(t, popped, 1)

			// confirmation timeout / not enough participants: the round
			// re-queues the popped intent as is
			require.NoError(t, store.Intents().Push(
				ctx, popped[0].Intent, popped[0].BoardingInputs, popped[0].CosignersPublicKeys,
			))

			// next round resets the cache: the pending removal from the
			// aborted round must not evict a vtxo that is queued again
			require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))

			found, err := store.Intents().IncludesAny(ctx, outpoints)
			require.NoError(t, err)
			require.NotEmpty(t, found)
			require.ElementsMatch(t, outpoints, found)

			require.NoError(t, store.Intents().Delete(ctx, []string{popped[0].Id}))

			found, err = store.Intents().IncludesAny(ctx, outpoints)
			require.NoError(t, err)
			require.Empty(t, found)
		})

		t.Run("popped input cannot be claimed by another intent", func(t *testing.T) {
			t.Cleanup(func() {
				require.NoError(t, store.Intents().DeleteAll(context.Background()))
			})

			require.NoError(t, pushIntent())

			popped, err := store.Intents().Pop(ctx, 1, testRoundId)
			require.NoError(t, err)
			require.Len(t, popped, 1)

			conflicting := popped[0].Intent
			conflicting.Id = uuid.New().String()

			err = store.Intents().Push(
				ctx, conflicting, popped[0].BoardingInputs, popped[0].CosignersPublicKeys,
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "duplicated input")

			require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))
		})

		t.Run("DeleteAll flushes pending guard set removals", func(t *testing.T) {
			require.NoError(t, pushIntent())

			popped, err := store.Intents().Pop(ctx, 1, testRoundId)
			require.NoError(t, err)
			require.Len(t, popped, 1)

			// admin flush while the round is in flight
			require.NoError(t, store.Intents().DeleteAll(ctx))

			found, err := store.Intents().IncludesAny(ctx, outpoints)
			require.NoError(t, err)
			require.Empty(t, found)

			// the same vtxo can be registered again by a new intent
			require.NoError(t, pushIntent())

			// draining the pending removals must not evict the vtxo still
			// referenced by the live intent
			require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))

			found, err = store.Intents().IncludesAny(ctx, outpoints)
			require.NoError(t, err)
			require.NotEmpty(t, found)
			require.ElementsMatch(t, outpoints, found)

			require.NoError(t, store.Intents().DeleteAll(ctx))
		})
	})

	// A note is an input like any other as far as double spending goes, so both
	// backends have to reject a second intent carrying one that is already
	// registered. The redis store used to skip notes when it filled and checked
	// its dedup set, which let two intents hold the same note at once.
	t.Run("IntentStoreNoteDedup", func(t *testing.T) {
		t.Run("rejects a second intent holding the same note", func(t *testing.T) {
			ctx := t.Context()

			noteVtxo := issueNoteVtxo(t, 10_000)
			noteOutpoint := noteVtxo.Outpoint
			first := noteIntent(noteVtxo)
			second := noteIntent(noteVtxo)

			require.NoError(t, store.Intents().Push(ctx, first, nil, nil))

			err := store.Intents().Push(ctx, second, nil, nil)
			require.Error(t, err, "a note already held by another intent must be rejected")
			require.Contains(t, err.Error(), "duplicated input")

			// The guard that asks whether any of a set of outpoints is already
			// spoken for reads the same set, so it has to see the note too.
			found, err := store.Intents().IncludesAny(ctx, []domain.Outpoint{noteOutpoint})
			require.NoError(t, err)
			require.NotEmpty(t, found)
			require.ElementsMatch(t, []domain.Outpoint{noteOutpoint}, found)

			require.NoError(t, store.Intents().Delete(ctx, []string{first.Id}))
		})

		// Deleting the holding intent is the failed-round path.
		t.Run("delete releases the note", func(t *testing.T) {
			ctx := t.Context()

			noteVtxo := issueNoteVtxo(t, 10_000)
			noteOutpoint := noteVtxo.Outpoint
			held := noteIntent(noteVtxo)
			require.NoError(t, store.Intents().Push(ctx, held, nil, nil))

			found, err := store.Intents().IncludesAny(ctx, []domain.Outpoint{noteOutpoint})
			require.NoError(t, err)
			require.NotEmpty(t, found)
			require.ElementsMatch(t, []domain.Outpoint{noteOutpoint}, found)

			require.NoError(t, store.Intents().Delete(ctx, []string{held.Id}))

			found, err = store.Intents().IncludesAny(ctx, []domain.Outpoint{noteOutpoint})
			require.NoError(t, err)
			require.Empty(t, found, "deleting the intent must release the note")

			retry := noteIntent(noteVtxo)
			require.NoError(
				t, store.Intents().Push(ctx, retry, nil, nil),
				"a released note must be registrable again",
			)
			require.NoError(t, store.Intents().Delete(ctx, []string{retry.Id}))
		})

		// Popping is the successful-round path, and it releases inputs in two
		// steps: Pop lists them, DeleteVtxos removes them. A note that never
		// made it into the set had nothing to remove, so this is the path that
		// would strand it once the set starts tracking notes.
		t.Run("pop then DeleteVtxos releases the note", func(t *testing.T) {
			ctx := t.Context()
			// Pop parks what it selected under its own key, and only DeleteAll
			// clears that. Leave the store as this subtest found it so a re-run
			// against the same redis starts from the same place. Cleanup runs
			// after t.Context is canceled, so it needs its own.
			t.Cleanup(func() {
				require.NoError(t, store.Intents().DeleteAll(context.Background()))
			})

			noteVtxo := issueNoteVtxo(t, 10_000)
			noteOutpoint := noteVtxo.Outpoint
			held := noteIntent(noteVtxo)
			require.NoError(t, store.Intents().Push(ctx, held, nil, nil))

			popped, err := store.Intents().Pop(ctx, 1, testRoundId)
			require.NoError(t, err)
			require.Len(t, popped, 1)
			require.Equal(t, held.Id, popped[0].Id)

			// Still claimed between the two steps: the round is in flight.
			found, err := store.Intents().IncludesAny(ctx, []domain.Outpoint{noteOutpoint})
			require.NoError(t, err)
			require.NotEmpty(t, found)
			require.ElementsMatch(t, []domain.Outpoint{noteOutpoint}, found)

			require.NoError(t, store.Intents().DeleteVtxos(ctx, testRoundId))

			found, err = store.Intents().IncludesAny(ctx, []domain.Outpoint{noteOutpoint})
			require.NoError(t, err)
			require.Empty(t, found, "DeleteVtxos must release the note")

			retry := noteIntent(noteVtxo)
			require.NoError(
				t, store.Intents().Push(ctx, retry, nil, nil),
				"a swept up note must be registrable again",
			)
			require.NoError(t, store.Intents().Delete(ctx, []string{retry.Id}))
		})

		// The set is what serializes two registrations racing for one note, so
		// exactly one of them may win no matter how they interleave.
		t.Run("only one of several concurrent intents gets the note", func(t *testing.T) {
			ctx := t.Context()
			const racers = 6

			noteVtxo := issueNoteVtxo(t, 10_000)
			intents := make([]domain.Intent, racers)
			for i := range intents {
				intents[i] = noteIntent(noteVtxo)
			}

			var wg sync.WaitGroup
			errs := make([]error, racers)
			start := make(chan struct{})
			for i := range racers {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					errs[i] = store.Intents().Push(ctx, intents[i], nil, nil)
				}(i)
			}
			close(start)
			wg.Wait()

			winners := make([]string, 0, 1)
			for i, err := range errs {
				if err == nil {
					winners = append(winners, intents[i].Id)
					continue
				}
				require.Contains(
					t, err.Error(), "duplicated input",
					"a loser must be turned away for the note, not for something else",
				)
			}
			require.Len(t, winners, 1, "exactly one intent may hold the note")

			require.NoError(t, store.Intents().Delete(ctx, winners))
		})
	})

	t.Run("ForfeitTxsStore", func(t *testing.T) {
		ctx := t.Context()

		connectors, intents, err := parseForfeitTxsFixture(connectorsJSON, intentsJSON)
		require.NoError(t, err)

		// Init
		err = store.ForfeitTxs().Init(ctx, testRoundId, connectors, intents)
		require.NoError(t, err)

		allSigned, err := store.ForfeitTxs().AllSigned(ctx)
		require.NoError(t, err)
		require.False(t, allSigned)

		txs := []string{tx1, tx2, tx3, tx4}

		// Concurrent Sign
		var wg sync.WaitGroup
		for _, tx := range txs {
			wg.Add(1)
			go func(txStr string) {
				defer wg.Done()
				err := store.ForfeitTxs().Sign(ctx, []string{txStr})
				require.NoError(t, err)
			}(tx)
		}
		wg.Wait()

		// AllSigned
		allSigned, err = store.ForfeitTxs().AllSigned(ctx)
		require.NoError(t, err)
		require.True(t, allSigned)
		unsigned, err := store.ForfeitTxs().GetUnsignedInputs(ctx)
		require.NoError(t, err)
		require.Empty(t, unsigned)

		forfeitsLen, err := store.ForfeitTxs().Len(ctx)
		require.NoError(t, err)
		require.Equal(t, 4, forfeitsLen)

		forfeits, err := store.ForfeitTxs().Pop(ctx)
		require.NoError(t, err)
		require.Equal(t, 4, len(forfeits))

		// Len
		forfeitsLen, err = store.ForfeitTxs().Len(ctx)
		require.NoError(t, err)
		require.Zero(t, forfeitsLen)

		err = store.ForfeitTxs().Reset(ctx)
		require.NoError(t, err)

		forfeitsLen, err = store.ForfeitTxs().Len(ctx)
		require.NoError(t, err)
		require.Zero(t, forfeitsLen)

		// redo the signing process but with delete in the middle
		err = store.ForfeitTxs().Init(ctx, testRoundId+"-next", connectors, intents)
		require.NoError(t, err)

		// all txs except the first
		var wg2 sync.WaitGroup
		for _, tx := range txs[1:] {
			wg2.Add(1)
			go func(txStr string) {
				defer wg2.Done()
				err := store.ForfeitTxs().Sign(ctx, []string{txStr})
				require.NoError(t, err)
			}(tx)
		}
		wg2.Wait()

		unsigned, err = store.ForfeitTxs().GetUnsignedInputs(ctx)
		require.NoError(t, err)
		require.Equal(t, []domain.Outpoint{intents[0].Inputs[0].Outpoint}, unsigned)

		err = store.ForfeitTxs().Reset(ctx)
		require.NoError(t, err)

		allSigned, err = store.ForfeitTxs().AllSigned(ctx)
		require.NoError(t, err)
		require.True(t, allSigned)

		// sign after the session is deleted
		require.Error(t, store.ForfeitTxs().Sign(ctx, []string{txs[0]}))

		allSigned, err = store.ForfeitTxs().AllSigned(ctx)
		require.NoError(t, err)
		require.True(t, allSigned)

		forfeitsLen, err = store.ForfeitTxs().Len(ctx)
		require.NoError(t, err)
		require.Zero(t, forfeitsLen)
	})

	t.Run("OffChainTxStore", func(t *testing.T) {
		ctx := t.Context()

		tx, err := parseOffchainTxFixture(offchainTxJSON)
		require.NoError(t, err)

		// Add
		err = store.OffchainTxs().Add(ctx, tx)
		require.NoError(t, err)

		// Get
		offchainTx, err := store.OffchainTxs().Get(ctx, "nonexistent")
		require.NoError(t, err)
		require.Nil(t, offchainTx)

		// Get
		offchainTx, err = store.OffchainTxs().Get(ctx, tx.ArkTxid)
		require.NoError(t, err)
		require.NotNil(t, offchainTx)

		// IncludesAny
		outpointJSON := `{"Txid":"fefcc1d90510aa15a77b3bac88a745f7cc58a02a1d4ebe631901bff7f327c51a","VOut":0}`
		var outpoint domain.Outpoint
		err = json.Unmarshal([]byte(outpointJSON), &outpoint)
		require.NoError(t, err)

		absent := domain.Outpoint{Txid: outpoint.Txid, VOut: outpoint.VOut + 1}
		included, err := store.OffchainTxs().IncludesAny(
			ctx, []domain.Outpoint{outpoint, absent, outpoint},
		)
		require.NoError(t, err)
		require.Equal(t, []domain.Outpoint{outpoint, outpoint}, included)

		included, err = store.OffchainTxs().IncludesAny(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, included)

		included, err = store.OffchainTxs().IncludesAny(ctx, []domain.Outpoint{absent})
		require.NoError(t, err)
		require.Empty(t, included)

		// Remove
		err = store.OffchainTxs().Remove(ctx, tx.ArkTxid)
		require.NoError(t, err)

		err = store.OffchainTxs().Remove(ctx, "nonexistent")
		require.NoError(t, err)

		// Get
		offchainTx, err = store.OffchainTxs().Get(ctx, tx.ArkTxid)
		require.NoError(t, err)
		require.Nil(t, offchainTx)
	})

	// The cosigned utxos store is a reservation set: AddUtxos claims all the given
	// outpoints or none of them, and a claim is released only by RemoveUtxos.
	t.Run("CosignedUtxosStore", func(t *testing.T) {
		ctx := t.Context()

		t.Run("add remove and includes any", func(t *testing.T) {
			outpoints := randomOutpoints(3)

			included, err := store.CosignedUtxos().IncludesAny(ctx, outpoints)
			require.NoError(t, err)
			require.Empty(t, included)

			included, err = store.CosignedUtxos().IncludesAny(ctx, nil)
			require.NoError(t, err)
			require.Empty(t, included)

			// Empty adds and removes are no-ops.
			require.NoError(t, store.CosignedUtxos().AddUtxos(ctx, nil))
			require.NoError(t, store.CosignedUtxos().RemoveUtxos(ctx, nil))

			require.NoError(t, store.CosignedUtxos().AddUtxos(ctx, outpoints))

			included, err = store.CosignedUtxos().IncludesAny(ctx, outpoints)
			require.NoError(t, err)
			require.ElementsMatch(t, outpoints, included)

			// Only the reserved ones are reported, in the order they were asked.
			other := randomOutpoints(2)
			included, err = store.CosignedUtxos().IncludesAny(
				ctx, []domain.Outpoint{other[0], outpoints[1], other[1]},
			)
			require.NoError(t, err)
			require.Equal(t, []domain.Outpoint{outpoints[1]}, included)

			// Adding again any of them is rejected as a whole: the fresh one is not
			// added either.
			err = store.CosignedUtxos().AddUtxos(ctx, []domain.Outpoint{other[0], outpoints[0]})
			require.ErrorIs(t, err, ports.ErrUtxosAlreadyExist)
			included, err = store.CosignedUtxos().IncludesAny(ctx, other)
			require.NoError(t, err)
			require.Empty(t, included)

			require.NoError(t, store.CosignedUtxos().RemoveUtxos(ctx, outpoints[:2]))
			included, err = store.CosignedUtxos().IncludesAny(ctx, outpoints)
			require.NoError(t, err)
			require.Equal(t, []domain.Outpoint{outpoints[2]}, included)

			// Removing unknown outpoints is a no-op.
			require.NoError(t, store.CosignedUtxos().RemoveUtxos(ctx, other))

			// Released outpoints can be reserved again.
			require.NoError(t, store.CosignedUtxos().AddUtxos(ctx, outpoints[:2]))
			require.NoError(t, store.CosignedUtxos().RemoveUtxos(ctx, outpoints))
		})

		// Many clients race to reserve the same outpoint: exactly one succeeds and
		// all the others get ErrUtxosAlreadyExist without leaving anything behind.
		t.Run("only one of several concurrent adds gets the utxo", func(t *testing.T) {
			contended := randomOutpoints(1)[0]
			const clients = 20

			var wg sync.WaitGroup
			errs := make([]error, clients)
			for i := range clients {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					// Each client claims the contended outpoint plus one of its own, so
					// a rejected claim must not leave its own outpoint behind.
					errs[i] = store.CosignedUtxos().AddUtxos(
						ctx, []domain.Outpoint{contended, ownOutpoint(i)},
					)
				}(i)
			}
			wg.Wait()

			winners := 0
			for i, err := range errs {
				included, incErr := store.CosignedUtxos().IncludesAny(
					ctx, []domain.Outpoint{ownOutpoint(i)},
				)
				require.NoError(t, incErr)
				if err == nil {
					winners++
					require.Len(t, included, 1, "winner %d must hold its own outpoint", i)
					continue
				}
				require.ErrorIs(t, err, ports.ErrUtxosAlreadyExist)
				require.Empty(t, included, "loser %d must not hold its own outpoint", i)
			}
			require.Equal(t, 1, winners)

			included, err := store.CosignedUtxos().IncludesAny(ctx, []domain.Outpoint{contended})
			require.NoError(t, err)
			require.Equal(t, []domain.Outpoint{contended}, included)
		})
	})

	t.Run("CurrentRoundStore", func(t *testing.T) {
		ctx := t.Context()
		r := domain.NewRound()

		// Upsert
		err := store.CurrentRound().Upsert(ctx, func(_ *domain.Round) *domain.Round { return r })
		require.NoError(t, err)

		// Get
		got, err := store.CurrentRound().Get(ctx)
		require.NoError(t, err)
		require.Equal(t, r.Id, got.Id)
	})

	t.Run("ConfirmationSessionsStore", func(t *testing.T) {
		ctx := t.Context()
		hashes := [][32]byte{h1, h2, h3, h4, h5}
		intentIds := []string{intentId1, intentId2, intentId3, intentId4, intentId5}

		err := store.ConfirmationSessions().Init(ctx, hashes)
		require.NoError(t, err)

		sessionCompleteCh := store.ConfirmationSessions().SessionCompleted()

		var wg sync.WaitGroup
		for _, intentId := range intentIds {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				err := store.ConfirmationSessions().Confirm(ctx, id)
				require.NoError(t, err)
			}(intentId)
		}
		wg.Wait()

		select {
		case <-time.After(5 * time.Second):
			require.Fail(t, "Confirmation session not completed")
		case <-sessionCompleteCh:
		}

		got, err := store.ConfirmationSessions().Get(ctx)
		require.NoError(t, err)
		require.Len(t, got.IntentsHashes, 5)
		require.Equal(t, 5, got.NumIntents)
		require.Equal(t, 5, got.NumConfirmedIntents)

		for _, hash := range hashes {
			confirmed, ok := got.IntentsHashes[hash]
			require.True(t, ok)
			require.True(t, confirmed)
		}

		err = store.ConfirmationSessions().Reset(ctx)
		require.NoError(t, err)

		// redo the confirmation process but with delete in the middle
		err = store.ConfirmationSessions().Init(ctx, hashes)
		require.NoError(t, err)

		sessionCompleteCh = store.ConfirmationSessions().SessionCompleted()

		// all confirmations except the first
		var wg2 sync.WaitGroup
		for _, intentId := range intentIds[1:] {
			wg2.Add(1)
			go func(id string) {
				defer wg2.Done()
				err := store.ConfirmationSessions().Confirm(ctx, id)
				require.NoError(t, err)
			}(intentId)
		}
		wg2.Wait()

		err = store.ConfirmationSessions().Reset(ctx)
		require.NoError(t, err)

		// confirm after the session is deleted
		require.Error(t, store.ConfirmationSessions().Confirm(ctx, intentIds[0]))

		event, ok := <-sessionCompleteCh
		require.False(t, ok)
		require.Empty(t, event)
	})

	t.Run("ConfirmationSessionsStore concurrent Confirm", func(t *testing.T) {
		ctx := t.Context()
		hashes := [][32]byte{h1, h2}

		// The first burst runs against a cold redis connection pool: one goroutine
		// grabs the only warm connection and completes its whole Confirm before the
		// other 19 finish dialing, so nothing overlaps and a racy Confirm would
		// still pass. Later rounds reuse the now-warm pool, making the confirms
		// truly concurrent; repeating 20x turns a probabilistic race into a
		// reliable failure.
		for round := range 20 {
			require.NoError(t, store.ConfirmationSessions().Init(ctx, hashes))

			start := make(chan struct{})
			errs := make(chan error, 20)
			var wg sync.WaitGroup
			for range 20 {
				wg.Go(func() {
					<-start
					errs <- store.ConfirmationSessions().Confirm(ctx, intentId1)
				})
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}

			got, err := store.ConfirmationSessions().Get(ctx)
			require.NoError(t, err)
			require.Equal(t, 1, got.NumConfirmedIntents, "round %d", round)
		}

		sessionCompleteCh := store.ConfirmationSessions().SessionCompleted()
		require.NoError(t, store.ConfirmationSessions().Confirm(ctx, intentId2))

		select {
		case <-time.After(5 * time.Second):
			require.Fail(t, "Confirmation session not completed")
		case <-sessionCompleteCh:
		}

		got, err := store.ConfirmationSessions().Get(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, got.NumConfirmedIntents)

		require.NoError(t, store.ConfirmationSessions().Reset(ctx))
	})

	t.Run("TreeSigningSessionsStore", func(t *testing.T) {
		ctx := t.Context()

		roundId1 := uuid.New().String()
		// New
		var uniqueSigners map[string]struct{}
		err := json.Unmarshal([]byte(uniqueSignersJSON), &uniqueSigners)
		require.NoError(t, err)
		err = store.TreeSigingSessions().New(ctx, roundId1, uniqueSigners, ports.SigningContext{})
		require.NoError(t, err)

		// Get
		sigSession, err := store.TreeSigingSessions().Get(ctx, roundId1)
		require.NoError(t, err)
		require.NotNil(t, sigSession)
		require.Equal(t, len(uniqueSigners)+1, sigSession.NbCosigners)

		noncesCollectedCh := store.TreeSigingSessions().NoncesCollected(roundId1)
		signaturesCollectedCh := store.TreeSigingSessions().SignaturesCollected(roundId1)
		doneCh := make(chan struct{})
		go func() {
			<-noncesCollectedCh
			<-signaturesCollectedCh
			doneCh <- struct{}{}
		}()

		type signer struct {
			pubkey string
			nonce  string
			sig    string
		}

		signers := []signer{
			{
				pubkey: "021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096",
				nonce:  n1,
				sig:    s1,
			},
			{
				pubkey: "039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67",
				nonce:  n2,
				sig:    s2,
			},
			{
				pubkey: "037f2214791b94cd517ccd561e739ebb73cecacdc41b387beb460dda197c2b7c67",
				nonce:  n3,
				sig:    s3,
			},
		}

		doSubmitNonces := func(signer signer, roundId string) error {
			nonces := make(tree.TreeNonces)
			err := json.Unmarshal([]byte(signer.nonce), &nonces)
			require.NoError(t, err)
			return store.TreeSigingSessions().AddNonces(ctx, roundId, signer.pubkey, nonces)
		}

		doSubmitSigs := func(signer signer, roundId string) error {
			sigs := make(tree.TreePartialSigs)
			err := json.Unmarshal([]byte(signer.sig), &sigs)
			require.NoError(t, err)
			return store.TreeSigingSessions().AddSignatures(ctx, roundId, signer.pubkey, sigs)
		}

		// unregistered cosigner must be rejected
		unknown := signer{
			pubkey: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			nonce:  n1,
			sig:    s1,
		}
		require.Error(t, doSubmitNonces(unknown, roundId1))
		require.Error(t, doSubmitSigs(unknown, roundId1))

		stopReads := make(chan struct{})
		go func() {
			for {
				select {
				case <-stopReads:
					return
				default:
					session, err := store.TreeSigingSessions().Get(ctx, roundId1)
					if err == nil && session != nil {
						for range session.Nonces {
						}
					}
				}
			}
		}()

		for _, signer := range signers {
			go func() {
				err := doSubmitNonces(signer, roundId1)
				require.NoError(t, err)
				err = doSubmitSigs(signer, roundId1)
				require.NoError(t, err)
			}()
		}

		select {
		case <-time.After(5 * time.Second):
			require.Fail(t, "signing session not completed")
		case <-doneCh:
		}
		close(stopReads)

		// Delete
		err = store.TreeSigingSessions().Delete(ctx, roundId1)
		require.NoError(t, err)

		// Get
		sigSession, err = store.TreeSigingSessions().Get(ctx, roundId1)
		require.NoError(t, err)
		require.Nil(t, sigSession)

		roundId2 := uuid.New().String()

		// redo the signing process but with delete in the middle
		err = store.TreeSigingSessions().New(ctx, roundId2, uniqueSigners, ports.SigningContext{})
		require.NoError(t, err)
		noncesCollectedCh = store.TreeSigingSessions().NoncesCollected(roundId2)
		signaturesCollectedCh = store.TreeSigingSessions().SignaturesCollected(roundId2)
		doneCh = make(chan struct{})

		// all signers except the first
		var wg sync.WaitGroup
		for _, signer := range signers[1:] {
			wg.Go(func() {
				err := doSubmitNonces(signer, roundId2)
				require.NoError(t, err)
				err = doSubmitSigs(signer, roundId2)
				require.NoError(t, err)
			})
		}
		wg.Wait()

		err = store.TreeSigingSessions().Delete(ctx, roundId2)
		require.NoError(t, err)

		// submit nonces and signatures after the session is deleted
		require.Error(t, doSubmitNonces(signers[0], roundId2))
		require.Error(t, doSubmitSigs(signers[0], roundId2))

		// channels should never return
		event, ok := <-noncesCollectedCh
		require.False(t, ok)
		require.Empty(t, event)

		event, ok = <-signaturesCollectedCh
		require.False(t, ok)
		require.Empty(t, event)

		// The collection threshold is re-reached on every resubmission, since a
		// cosigner overwriting its own entry leaves the count unchanged, while the
		// coordinator receives at most once. Submitting again must not block.
		roundId3 := uuid.New().String()
		require.NoError(t, store.TreeSigingSessions().New(ctx, roundId3, uniqueSigners, ports.SigningContext{}))

		collected := make(chan struct{})
		go func() {
			<-store.TreeSigingSessions().NoncesCollected(roundId3)
			<-store.TreeSigingSessions().SignaturesCollected(roundId3)
			close(collected)
		}()

		// submitted from the test goroutine so failures are reported normally
		for _, signer := range signers {
			require.NoError(t, doSubmitNonces(signer, roundId3))
		}
		for _, signer := range signers {
			require.NoError(t, doSubmitSigs(signer, roundId3))
		}

		select {
		case <-collected:
		case <-time.After(5 * time.Second):
			require.Fail(t, "collection was never signalled")
		}

		// nobody is receiving now: resubmitting must return rather than park
		nonceResubmit := make(chan error, 1)
		sigResubmit := make(chan error, 1)
		go func() {
			nonceResubmit <- doSubmitNonces(signers[0], roundId3)
			sigResubmit <- doSubmitSigs(signers[0], roundId3)
		}()
		select {
		case err := <-nonceResubmit:
			require.Error(t, err, "nonce resubmission must be rejected, not overwrite")
		case <-time.After(5 * time.Second):
			require.Fail(t, "nonce resubmission after collection blocked")
		}
		select {
		case err := <-sigResubmit:
			require.NoError(t, err, "signature resubmission must succeed")
		case <-time.After(5 * time.Second):
			require.Fail(t, "signature resubmission after collection blocked")
		}

		require.NoError(t, store.TreeSigingSessions().Delete(ctx, roundId3))
	})

	t.Run("BoardingInputsStore", func(t *testing.T) {
		ctx := t.Context()

		err := store.BoardingInputs().Set(ctx, 42)
		require.NoError(t, err)

		numBoardingIns, err := store.BoardingInputs().Get(ctx)
		require.NoError(t, err)
		require.Equal(t, 42, numBoardingIns)

		err = store.BoardingInputs().Set(ctx, 0)
		require.NoError(t, err)

		numBoardingIns, err = store.BoardingInputs().Get(ctx)
		require.NoError(t, err)
		require.Zero(t, numBoardingIns)

		batchId := "fakeCommitmentTxid"
		type signerSigs struct {
			inputIndex uint32
			sigs       map[uint32]ports.SignedBoardingInput
		}

		signers := []signerSigs{
			{
				inputIndex: 0,
				sigs: map[uint32]ports.SignedBoardingInput{
					0: {
						Signatures: []*psbt.TaprootScriptSpendSig{
							{
								XOnlyPubKey: []byte{0},
								LeafHash:    []byte{1},
								Signature:   []byte{2},
								SigHash:     txscript.SigHashAll,
							},
						},
						LeafScript: &psbt.TaprootTapLeafScript{
							ControlBlock: []byte{3},
							Script:       []byte{4},
							LeafVersion:  0,
						},
					},
				},
			},
			{
				inputIndex: 1,
				sigs: map[uint32]ports.SignedBoardingInput{
					1: {
						Signatures: []*psbt.TaprootScriptSpendSig{
							{
								XOnlyPubKey: []byte{5},
								LeafHash:    []byte{6},
								Signature:   []byte{7},
								SigHash:     txscript.SigHashAll,
							},
						},
						LeafScript: &psbt.TaprootTapLeafScript{
							ControlBlock: []byte{8},
							Script:       []byte{9},
							LeafVersion:  0,
						},
					},
				},
			},
			{
				inputIndex: 2,
				sigs: map[uint32]ports.SignedBoardingInput{
					2: {
						Signatures: []*psbt.TaprootScriptSpendSig{
							{
								XOnlyPubKey: []byte{10},
								LeafHash:    []byte{11},
								Signature:   []byte{12},
								SigHash:     txscript.SigHashAll,
							},
						},
						LeafScript: &psbt.TaprootTapLeafScript{
							ControlBlock: []byte{13},
							Script:       []byte{14},
							LeafVersion:  0,
						},
					},
				},
			},
		}

		expectedSigs := map[uint32]ports.SignedBoardingInput{
			0: {
				Signatures: []*psbt.TaprootScriptSpendSig{
					{
						XOnlyPubKey: []byte{0},
						LeafHash:    []byte{1},
						Signature:   []byte{2},
						SigHash:     txscript.SigHashAll,
					},
				},
				LeafScript: &psbt.TaprootTapLeafScript{
					ControlBlock: []byte{3},
					Script:       []byte{4},
					LeafVersion:  0,
				},
			},
			1: {
				Signatures: []*psbt.TaprootScriptSpendSig{
					{
						XOnlyPubKey: []byte{5},
						LeafHash:    []byte{6},
						Signature:   []byte{7},
						SigHash:     txscript.SigHashAll,
					},
				},
				LeafScript: &psbt.TaprootTapLeafScript{
					ControlBlock: []byte{8},
					Script:       []byte{9},
					LeafVersion:  0,
				},
			},
			2: {
				Signatures: []*psbt.TaprootScriptSpendSig{
					{
						XOnlyPubKey: []byte{10},
						LeafHash:    []byte{11},
						Signature:   []byte{12},
						SigHash:     txscript.SigHashAll,
					},
				},
				LeafScript: &psbt.TaprootTapLeafScript{
					ControlBlock: []byte{13},
					Script:       []byte{14},
					LeafVersion:  0,
				},
			},
		}

		overWrittenSigs := map[uint32]ports.SignedBoardingInput{
			0: {
				Signatures: []*psbt.TaprootScriptSpendSig{
					{
						XOnlyPubKey: []byte{99},
						LeafHash:    []byte{99},
						Signature:   []byte{99},
						SigHash:     txscript.SigHashAll,
					},
				},
				LeafScript: &psbt.TaprootTapLeafScript{
					ControlBlock: []byte{99},
					Script:       []byte{99},
					LeafVersion:  0,
				},
			},
		}

		gotSigs, err := store.BoardingInputs().GetSignatures(ctx, batchId)
		require.NoError(t, err)
		require.Empty(t, gotSigs)

		// multiple signers submit at the same time
		var wg sync.WaitGroup
		for _, signer := range signers {
			wg.Add(1)
			go func(signer signerSigs) {
				defer wg.Done()
				err := store.BoardingInputs().AddSignatures(ctx, batchId, signer.sigs)
				require.NoError(t, err)
			}(signer)
		}
		wg.Wait()

		// verify all signatures were collected correctly
		gotSigs, err = store.BoardingInputs().GetSignatures(ctx, batchId)
		require.NoError(t, err)
		require.NotEmpty(t, gotSigs)
		require.NoError(t, sigsMatch(expectedSigs, gotSigs))

		// try to overwrite concurrently
		var overwriteWg sync.WaitGroup
		for range 3 {
			overwriteWg.Go(func() {
				err := store.BoardingInputs().AddSignatures(ctx, batchId, overWrittenSigs)
				require.NoError(t, err)
			})
		}
		overwriteWg.Wait()

		// verify original signatures are still there (not overwritten)
		gotSigs, err = store.BoardingInputs().GetSignatures(ctx, batchId)
		require.NoError(t, err)
		require.NotEmpty(t, gotSigs)
		require.NoError(t, sigsMatch(expectedSigs, gotSigs))

		err = store.BoardingInputs().DeleteSignatures(ctx, batchId)
		require.NoError(t, err)

		gotSigs, err = store.BoardingInputs().GetSignatures(ctx, batchId)
		require.NoError(t, err)
		require.Empty(t, gotSigs)
	})

	t.Run("SettingsStore", func(t *testing.T) {
		ctx := t.Context()

		// Get on an unset store returns nil, nil for both backends.
		got, err := store.Settings().Get(ctx)
		require.NoError(t, err)
		require.Nil(t, got)

		baseline := ports.Settings{
			Settings: domain.Settings{
				SessionDuration: 60 * time.Second,
				VtxoMinAmount:   1000,
				VtxoMaxAmount:   1_000_000,
			},
			Network:    arklib.BitcoinRegTest,
			DustAmount: 1000,
		}

		// Upsert then Get round-trips the settings.
		err = store.Settings().Upsert(ctx, baseline)
		require.NoError(t, err)

		afterUpsert, err := store.Settings().Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, afterUpsert)
		require.EqualValues(t, 60*time.Second, afterUpsert.SessionDuration)
		require.Equal(t, arklib.BitcoinRegTest, afterUpsert.Network)
		require.True(t, afterUpsert.LastBatchAt.IsZero())
		require.Empty(t, afterUpsert.LastBatchId)

		// UpdateLastBatch sets only LastBatchAt/LastBatchId. A whole-second time
		// is used so the value survives the redis DTO's Unix-seconds encoding and
		// compares equal for both backends.
		at := time.Unix(1700000000, 0)
		roundId := "round-123"
		err = store.Settings().UpdateLastBatch(ctx, at, roundId)
		require.NoError(t, err)

		afterUpdate, err := store.Settings().Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, afterUpdate)
		require.True(t, afterUpdate.LastBatchAt.Equal(at))
		require.Equal(t, roundId, afterUpdate.LastBatchId)

		// Everything except the last-batch fields is preserved: normalise those
		// two fields on the pre-update snapshot and the two must be identical.
		afterUpsert.LastBatchAt = afterUpdate.LastBatchAt
		afterUpsert.LastBatchId = afterUpdate.LastBatchId
		require.Equal(t, afterUpsert, afterUpdate)
	})
}

type intentPushFixture struct {
	Intent              domain.Intent         `json:"intent"`
	BoardingInputs      []ports.BoardingInput `json:"boardingInputs"`
	CosignersPublicKeys []string              `json:"cosignerPubkeys"`
}

const intentPubkey = "7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"

func randomOutpoints(n int) []domain.Outpoint {
	outpoints := make([]domain.Outpoint, 0, n)
	for i := range n {
		outpoints = append(outpoints, domain.Outpoint{Txid: randomIntentTxid(), VOut: uint32(i)})
	}
	return outpoints
}

// ownOutpoint is the outpoint client i claims alongside the contended one in the
// concurrent add test.
func ownOutpoint(i int) domain.Outpoint {
	return domain.Outpoint{Txid: fmt.Sprintf("own-%d", i), VOut: 0}
}

// vtxoInput builds a settleable vtxo input. It carries a commitment, so
// IsNote is false for it.
func vtxoInput() domain.Vtxo {
	return domain.Vtxo{
		Outpoint:           domain.Outpoint{Txid: randomIntentTxid(), VOut: 0},
		PubKey:             intentPubkey,
		Amount:             1000,
		RootCommitmentTxid: "commitment",
		CommitmentTxids:    []string{"commitment"},
	}
}

// boardingInputs builds a boarding input, held like a vtxo input but reaching
// Push through its own argument.
func boardingInputs() []ports.BoardingInput {
	return []ports.BoardingInput{{
		Input: ports.Input{
			Outpoint:   domain.Outpoint{Txid: randomIntentTxid(), VOut: 1},
			Tapscripts: []string{"00"},
		},
		Amount: 1000,
	}}
}

// boardingIntent is an intent with no vtxo inputs at all, for the cases where
// the only thing held is a boarding input.
func boardingIntent() domain.Intent {
	return domain.Intent{
		Id:        uuid.New().String(),
		Receivers: []domain.Receiver{{Amount: 1000, PubKey: intentPubkey}},
	}
}

func intentWith(inputs ...domain.Vtxo) domain.Intent {
	receivers := make([]domain.Receiver, 0, len(inputs))
	for _, input := range inputs {
		receivers = append(
			receivers, domain.Receiver{Amount: input.Amount, PubKey: input.PubKey},
		)
	}
	return domain.Intent{
		Id:        uuid.New().String(),
		Inputs:    inputs,
		Receivers: receivers,
	}
}

func randomIntentTxid() string {
	buf := make([]byte, 32)
	// nolint:errcheck
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func noteIntent(vtxo domain.Vtxo) domain.Intent {
	return domain.Intent{
		Id:     uuid.New().String(),
		Inputs: []domain.Vtxo{vtxo},
		Receivers: []domain.Receiver{
			{Amount: vtxo.Amount, PubKey: vtxo.PubKey},
		},
	}
}

// issueNoteVtxo mints a note and shapes it into the vtxo row that
// adminService.CreateNotes persists, so these cases run against the input the
// issuing API actually produces rather than a stand in. That row carries no
// commitment, which is what makes IsNote true and what put it on the wrong side
// of the guard this change removes.
func issueNoteVtxo(t *testing.T, value uint32) domain.Vtxo {
	t.Helper()

	n, err := note.NewNote(value)
	require.NoError(t, err)
	outpoint, pInput, err := n.IntentProofInput()
	require.NoError(t, err)

	vtxo := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: outpoint.Hash.String(), VOut: outpoint.Index},
		Amount:   uint64(n.Value),
		PubKey:   hex.EncodeToString(pInput.WitnessUtxo.PkScript[2:]),
	}
	require.True(t, vtxo.IsNote(), "an issued note must be an IsNote vtxo")
	require.False(t, vtxo.RequiresForfeit(), "no forfeit tx binds a note")

	return vtxo
}

func parseIntentFixtures(fixtureJSON string) (*intentPushFixture, error) {
	var fixture intentPushFixture
	if err := json.Unmarshal([]byte(fixtureJSON), &fixture); err != nil {
		return nil, err
	}
	return &fixture, nil
}

func parseForfeitTxsFixture(
	connectorsJSON, intentsJSON string,
) (tree.FlatTxTree, []domain.Intent, error) {
	nodes := make(tree.FlatTxTree, 0)
	if err := json.Unmarshal([]byte(connectorsJSON), &nodes); err != nil {
		return nil, nil, err
	}

	var intents []domain.Intent
	if err := json.Unmarshal([]byte(intentsJSON), &intents); err != nil {
		return nil, nil, err
	}

	return nodes, intents, nil
}

func parseOffchainTxFixture(txJSON string) (domain.OffchainTx, error) {
	var tx domain.OffchainTx
	if err := json.Unmarshal([]byte(txJSON), &tx); err != nil {
		return domain.OffchainTx{}, err
	}

	return tx, nil
}

type mockedTxBuilder struct {
	ports.TxBuilder
	verify func([]string) (map[domain.Outpoint]ports.ValidForfeitTx, error)
}

func (m *mockedTxBuilder) VerifyAndRebuildForfeitTxs(
	_ []domain.Vtxo, _ tree.FlatTxTree, txs []string,
) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
	return m.verify(txs)
}

func intentsEqual(t *testing.T, a, b []ports.TimedIntent) {
	require.Equal(t, len(a), len(b))
	hashesA := make(map[string]bool)
	hashesB := make(map[string]bool)
	for _, intent := range a {
		hashId := intent.HashID()
		hashesA[hex.EncodeToString(hashId[:])] = true
	}
	for _, intent := range b {
		hashId := intent.HashID()
		hashesB[hex.EncodeToString(hashId[:])] = true
	}
	require.Equal(t, hashesA, hashesB)
}

func sigsMatch(sigs, gotSigs map[uint32]ports.SignedBoardingInput) error {
	for inIndex, sig := range sigs {
		gotSig, ok := gotSigs[inIndex]
		if !ok {
			return fmt.Errorf("missing sigs for input index %d", inIndex)
		}
		if len(sig.Signatures) != len(gotSig.Signatures) {
			return fmt.Errorf(
				"input %d: got %d signatures, expected %d",
				inIndex, len(gotSig.Signatures), len(sig.Signatures),
			)
		}
		for i, s := range sig.Signatures {
			gotS := gotSig.Signatures[i]
			if !bytes.Equal(s.XOnlyPubKey, gotS.XOnlyPubKey) {
				return fmt.Errorf(
					"input %d - sig %d: got %x xonly pubkey, expected %x",
					inIndex, i, gotS.XOnlyPubKey, s.XOnlyPubKey,
				)
			}
			if !bytes.Equal(s.LeafHash, gotS.LeafHash) {
				return fmt.Errorf(
					"input %d - sig %d: got %x leaf hash, expected %x",
					inIndex, i, gotS.LeafHash, s.LeafHash,
				)
			}
			if !bytes.Equal(s.Signature, gotS.Signature) {
				return fmt.Errorf(
					"input %d - sig %d: got %x signature, expected %x",
					inIndex, i, gotS.Signature, s.Signature,
				)
			}
			if s.SigHash != gotS.SigHash {
				return fmt.Errorf(
					"input %d - sig %d: got %d sighash type, expected %d",
					inIndex, i, gotS.SigHash, s.SigHash,
				)
			}
		}
		ls := sig.LeafScript
		gotLS := gotSig.LeafScript
		if !bytes.Equal(ls.ControlBlock, gotLS.ControlBlock) {
			return fmt.Errorf(
				"input %d - leaf script: got %x control block, expected %x",
				inIndex, gotLS.ControlBlock, ls.ControlBlock,
			)
		}
		if !bytes.Equal(ls.Script, gotLS.Script) {
			return fmt.Errorf(
				"input %d - leaf script: got %x script, expected %x",
				inIndex, gotLS.Script, ls.Script,
			)
		}
		if ls.LeafVersion != gotLS.LeafVersion {
			return fmt.Errorf(
				"input %d - leaf script: got %d leaf version, expected %d",
				inIndex, gotLS.LeafVersion, ls.LeafVersion,
			)
		}
	}
	return nil
}
