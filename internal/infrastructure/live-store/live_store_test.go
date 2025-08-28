package livestore_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	inmemory "github.com/arkade-os/arkd/internal/infrastructure/live-store/inmemory"
	redislivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/redis"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/redis/go-redis/v9"

	"github.com/stretchr/testify/require"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"

	"github.com/stretchr/testify/mock"
)

var (
	connectorsJSON = `[{"Tx":"cHNidP8BAOwDAAAAAcXuArkhSrxO59ox0sKDFr0zZzeJuIImgzIGH5oiKx63AQAAAAD/////BU0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhFNAQAAAAAAACJRIIuBxfGXLJBxAcCzUNERqM25pggGv/bwyR8wuLMXmQ4RTQEAAAAAAAAiUSCLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEU0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAAAAAA==","Children":{"0":"5e1eae3436fa3175eb238b3cc22cfccd17ec32c8f6cfd911e03f58f83b05fd7b","1":"8c8c00c0b0966880a8e9dacd8e266f3ddf938e817c7bd40295bddc5e45d900ea","2":"584408db5ed86cd5c51e2f6f027fa40a6584c3c91b8103d45ae36bc55d8a7329","3":"cbeecbaa2cd83534762c7720b29ad8e4fd9bca7e6d1a26a41a2fe0f48ef7bd6f"}},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AAAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{}},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AQAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{}},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AgAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{}},{"Tx":"cHNidP8BAGsDAAAAASE8O6xJeYeQ6L6Z4CHN1ndN3as+fOX/CPvGJ4tcn/e0AwAAAAD/////Ak0BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAAAAAAAAAARRAk5zAAAAAAAMY29zaWduZXIAAAAAIQKLgcXxlyyQcQHAs1DREajNuaYIBr/28MkfMLizF5kOEQAAAA==","Children":{}}]`
	intentsJSON    = `[{"Id":"d4d1735d-05d1-493c-ac3a-b0bb634a50fe","Inputs":[{"Txid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","VOut":0,"Amount":5000,"PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpireAt":199,"Preconfirmed": true,"CreatedAt":1749818677},{"Txid":"c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198","VOut":1,"Amount":99997000,"PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpireAt":199,"Preconfirmed":true,"CreatedAt":1749818677}],"Receivers":[{"Amount":100002000,"OnchainAddress":"","PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24"}]},{"Id":"6eef6c69-179c-4fe8-b183-e79637838255","Inputs":[{"Txid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","VOut":1,"Amount":99995000,"PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpireAt":199,"Preconfirmed":true,"CreatedAt":1749818677},{"Txid":"c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198","VOut":0,"Amount":3000,"PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63","RootCommitmentTxid":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","CommitmentTxids":["2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"],"SpentBy":"","Spent":false,"Unrolled":false,"Swept":false,"ExpireAt":199,"Preconfirmed":true,"CreatedAt":1749818677}],"Receivers":[{"Amount":99998000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}]`
	tx1            = "cHNidP8BAIgDAAAAAnv9BTv4WD/gEdnP9sgy7BfN/CzCPIsj63Ux+jY0rh5eAAAAAAD/////q7i/0+MBfAFLRcdx3UBTTlCHIFJ4B3hpDUU0e/lL53kAAAAAAP////8C1RQAAAAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEriBMAAAAAAAAiUSBwhtcqjdrMnm4EUdkhM+9YPWdIpHJrYyqU8m34yAKsJEEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUAMWsyNnOkGuXqv1tZryHrR2opcv1IE8y8vd0plIWjcBzC75lIIeMaV3QLOicJkpx854Hpb4hdGylSRnw9wTDBjQhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDAx+14WC2NF93SA39AJr+zuMBDbBkzxBXNHpuv/6Dnb0UgLyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1StIDaW50nxJTR9gvLAoXOmCm76EX2uxlTKpPeMF5TI/Q8jrMAAAAA="
	tx2            = "cHNidP8BAIgDAAAAAm+994704C8apCYabX7Km/3k2JqyIHcsdjQ12Cyqy+7LAAAAAAD/////mNHiF2WGWq/0gRn7RfOw496tjW4WB99qKuyVHa4XrsQBAAAAAP////8Cldb1BQAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQErSNX1BQAAAAAiUSBwhtcqjdrMnm4EUdkhM+9YPWdIpHJrYyqU8m34yAKsJEEULyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1SL45HbEaCf+ZMY3cfCc6bLe13jWNIJgi8nTS2+Lw+zIUASzdEkMZS1M3JBzp2N/ky+nki8GRJ5WpQY/7UZLI8AuFe0+26NmFuwbCdABpfu0vbRcwgKOS+9B3Fot0jlBLP5QhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDAx+14WC2NF93SA39AJr+zuMBDbBkzxBXNHpuv/6Dnb0UgLyriza1giT7HPFxEqbI6St3+hZuq8XVP4ZPaJ/Mep1StIDaW50nxJTR9gvLAoXOmCm76EX2uxlTKpPeMF5TI/Q8jrMAAAAA="
	tx3            = "cHNidP8BAIgDAAAAAuoA2UVe3L2VAtR7fIGOk989byaOzdrpqIBolrDAAIyMAAAAAAD/////q7i/0+MBfAFLRcdx3UBTTlCHIFJ4B3hpDUU0e/lL53kBAAAAAP////8Cxc71BQAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEreM31BQAAAAAiUSB1lMms2ZbM9mdDF2m7SyOLKantMrc/ORhcEhz3cKoKY0EU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDpuqwgR4YEuiemShPyiNdDm0AX1aj0sm1E5JUWApXGIahSpPpWhImz2GlO+PMJHdVNXEKXoDePj91v6H6PK1a0QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQInUzArzkE6X+bP/eCF7F1PzaedGuM4wtX5roc9fOZ1Ja0XTErh5GUWMdZUGaqIDBlbggnPZjidgCFpV1DlEry5CFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSAvKuLNrWCJPsc8XESpsjpK3f6Fm6rxdU/hk9on8x6nVK0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIC8q4s2tYIk+xzxcRKmyOkrd/oWbqvF1T+GT2ifzHqdUrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAA="
	tx4            = "cHNidP8BAIgDAAAAAilzil3Fa+Na1AOBG8nDhGUKpH8Cby8exdVs2F7bCERYAAAAAAD/////mNHiF2WGWq/0gRn7RfOw496tjW4WB99qKuyVHa4XrsQAAAAAAP////8CBQ0AAAAAAAAWABQrwBxZxFNQ+DSDSqacn20LIQKLrQAAAAAAAAAABFECTnMAAAAAAAEBK00BAAAAAAAAIlEgi4HF8ZcskHEBwLNQ0RGozbmmCAa/9vDJHzC4sxeZDhEAAQEruAsAAAAAAAAiUSB1lMms2ZbM9mdDF2m7SyOLKantMrc/"

	intentFixture1 = `{"boardingInputs":[{"Txid":"1e1448b9f2c44e4bc861db45864097d94fa7519dab9cba12c886a0c244932145","VOut":1,"Tapscripts":["039d0440b27520fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4eac","20fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4ead203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67"],"intent":{"Id":"0222bfa8-c753-4b41-a5f9-d4e12d726413","Inputs":[{"Txid":"24de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10da","VOut":0,"RootCommitmentTxid":"0000000000000000000000000000000000000000000000000000000000000000","CommitmentTxids":["0000000000000000000000000000000000000000000000000000000000000000"]}],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}}`
	intentFixture2 = `{"boardingInputs":[{"Txid":"14de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10db","VOut":1,"Tapscripts":["039d0440b275202f2ae2cdad60893ec73c5c44a9b23a4addfe859baaf1754fe193da27f31ea754ac","202f2ae2cdad60893ec73c5c44a9b23a4addfe859baaf1754fe193da27f31ea754ad203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096"],"intent":{"Id":"2a4d69f3-ce1b-40b3-a48d-fb61ec21b15f","Inputs":[],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7086d72a8ddacc9e6e0451d92133ef583d6748a4726b632a94f26df8c802ac24"}]}}`
	intentFixture3 = `{"boardingInputs":[{"Txid":"1e1448b9f2c44e4bc861db45864097d94fa7519dab9cba12c886a0c244932145","VOut":1,"Tapscripts":["039d0440b27520fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4eac","20fa8c9a09b46c5ee858e239684b0bb7229c7d38f1fc05b3e3ef04ddff6d4e5a4ead203696e749f125347d82f2c0a173a60a6efa117daec654caa4f78c1794c8fd0f23ac"],"Amount":100000000}],"cosignerPubkeys":["039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67"],"intent":{"Id":"aaaaaaaa-c753-4b41-a5f9-d4e12d726413","Inputs":[{"Txid":"24de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10da","VOut":0,"RootCommitmentTxid":"0000000000000000000000000000000000000000000000000000000000000000","CommitmentTxids":["0000000000000000000000000000000000000000000000000000000000000000"]}],"Receivers":[{"Amount":100000000,"OnchainAddress":"","PubKey":"7594c9acd996ccf667431769bb4b238b29a9ed32b73f39185c121cf770aa0a63"}]}}`

	offchainTxJSON = `{"Stage":{"Code":2,"Ended":false,"Failed":false},"StartingTimestamp":1749818677,"EndingTimestamp":0,"ArkTxid":"79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab","ArkTx":"cHNidP8BAJYDAAAAAeB4gUdsoDHu7o2F4IkLICEbEt0y9MejPi5mWzdZtxBBAAAAAAD/////A4gTAAAAAAAAIlEgcIbXKo3azJ5uBFHZITPvWD1nSKRya2MqlPJt+MgCrCR4zfUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjAAAAAAAAAAAEUQJOcwAAAAAAAQErAOH1BQAAAAAiUSDTwlo9WBKfqLWlkkznHmITfQzQEU37+YWWyqn5B2dyGEEU+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk4MjR6TYePp/0T4p433ieP80aFTXXPgoCOHPjELdrL+AUDpuqwgR4YEuiemShPyiNdDm0AX1aj0sm1E5JUWApXGIahSpPpWhImz2GlO+PMJHdVNXEKXoDePj91v6H6PK1a0QRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQInUzArzkE6X+bP/eCF7F1PzaedGuM4wtX5roc9fOZ1Ja0XTErh5GUWMdZUGaqIDBlbggnPZjidgCFpV1DlEry5CFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOlm8s7rZPsauycdJTy6UH8o1nvcz68gOYxt8V80njVkRSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUgNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOsAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAAA","CheckpointTxs":{"4110b759375b662e3ea3c7f432dd121b21200b89e0858deeee31a06c478178e0":"cHNidP8BAGsDAAAAARrFJ/P3vwEZY75OHSqgWMz3RaeIrDt7pxWqEAXZwfz+AAAAAAD/////AgDh9QUAAAAAIlEg08JaPVgSn6i1pZJM5x5iE30M0BFN+/mFlsqp+QdnchgAAAAAAAAAAARRAk5zAAAAAAABASsA4fUFAAAAACJRIHWUyazZlsz2Z0MXabtLI4spqe0ytz85GFwSHPdwqgpjQRQ2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PIwyNHpNh4+n/RPinjfeJ4/zRoVNdc+CgI4c+MQt2sv4BQCgwEdt3LF/ub7J1hnF3+kbMvbo0Wqt3VpGDsto8wiqy6KL6zHMxKYEZAn1z3SLCo7wKZFsWk1gdx65rINE5JM5CFcBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wHYMhmDVZUYnxrCdnty+DMhKJTmw60ZDqTPzCAavjN5ERSD6jJoJtGxe6FjiOWhLC7cinH048fwFs+PvBN3/bU5aTq0gNpbnSfElNH2C8sChc6YKbvoRfa7GVMqk94wXlMj9DyOswAd0YXB0cmVlcwIBwCgDAgBAsnUg+oyaCbRsXuhY4jloSwu3Ipx9OPH8BbPj7wTd/21OWk6sAcBEIPqMmgm0bF7oWOI5aEsLtyKcfTjx/AWz4+8E3f9tTlpOrSA2ludJ8SU0fYLywKFzpgpu+hF9rsZUyqT3jBeUyP0PI6wAAAA="},"CommitmentTxids":{"4110b759375b662e3ea3c7f432dd121b21200b89e0858deeee31a06c478178e0":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96"},"RootCommitmentTxId":"2c6bffc1ce2da7e40f37043b7940b548b9b93f474e17c7fd84c8090c054afc96","ExpiryTimestamp":199,"FailReason":"","Version":0}`

	h1 = sha256.Sum256([]byte("fdbc502adf42a40dc7c0b2d3b50b9c0b01f9c386dc9bef5233bc9f39acdf48ae"))
	h2 = sha256.Sum256([]byte("340f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff"))

	roundId           = "218767a7-bceb-4f79-90e7-ad07ddccf246"
	uniqueSignersJSON = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":{},"039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":{}}`

	n1 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"025232ea8243113a0cf3a70369f1ca785da06302268a9cab7d20864faf2b892b03234f9f4155bc2d8c4ee7c7e0989dc7a4a4d3a680f352ed05d1091188647c46c101","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"0379d69fa1c63ae8cf9026420fca3fc2728d20fcae5597bfeca6c63884feadcbb4028eb4eaa685ca3ee6fdbd949374a98a505c5c0774f8d410ece28c11572396819d"}`
	n2 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"03489a9e200420f9ae1bb96731cf6d4ecdaa694d816abbbdaa671ac4786f9e79c6403f9361c16a0ad701eb0ee814d9d52928acb1624f38c3b3e89fa35acdb8c6e490","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"03707efe23bc97f17969a5d18c0ddf7223f38dab4b043dbe56a8a9e5b5dc709be3022627414c8c036aafc683ba00a3435b11fb6bda5b4a582e271c7deadfafe0abda"}`

	s1 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"74df3c018f86c004e9ecc6bbfe58a958753579f5a5feb3a8ed8dc5c9d4dba5c2","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"2cf641ff3a26702fc0a01bc9fb500b6ca9e79bfd88a31f0569c4767203a75707"}`
	s2 = `{"021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096":"c1d480aff75d86460a6f8864782222d05d39b83e4c413c76280e52a09922fe15","039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67":"89c6cbcab945d54f345513338278734c66f94d38016dc1c9842c8a7a2e32d829"}`

	validTx = map[domain.Outpoint]ports.ValidForfeitTx{
		{Txid: "79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab", VOut: 0}: {
			Tx:        "tx1",
			Connector: domain.Outpoint{Txid: "conn1", VOut: 0},
		},
		{Txid: "c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198", VOut: 1}: {
			Tx:        "tx2",
			Connector: domain.Outpoint{Txid: "conn2", VOut: 0},
		},
		{Txid: "79e74bf97b34450d69780778522087504e5340dd71c7454b017c01e3d3bfb8ab", VOut: 1}: {
			Tx:        "tx3",
			Connector: domain.Outpoint{Txid: "conn2", VOut: 1},
		},
		{Txid: "c4ae17ae1d95ec2a6adf07166e8daddee3b0f345fb1981f4af5a866517e2d198", VOut: 0}: {
			Tx:        "tx4",
			Connector: domain.Outpoint{Txid: "conn3", VOut: 0},
		},
	}
)

func TestLiveStoreImplementations(t *testing.T) {
	redisOpts, err := redis.ParseURL("redis://localhost:6379/0")
	require.NoError(t, err)
	rdb := redis.NewClient(redisOpts)

	txBuilder := new(mockedTxBuilder)
	txBuilder.On("VerifyForfeitTxs", mock.Anything, mock.Anything, mock.Anything).
		Return(validTx, nil)

	stores := []struct {
		name  string
		store ports.LiveStore
	}{
		{"inmemory", inmemory.NewLiveStore(txBuilder)},
		{"redis", redislivestore.NewLiveStore(rdb, txBuilder, 5)},
	}

	for _, tt := range stores {
		t.Run(tt.name, func(t *testing.T) {
			runLiveStoreTests(t, tt.store)
		})
	}
}

func runLiveStoreTests(t *testing.T, store ports.LiveStore) {
	t.Run("IntentStore", func(t *testing.T) {
		intent1, err := parseIntentFixtures(intentFixture1)
		require.NoError(t, err)
		intent2, err := parseIntentFixtures(intentFixture2)
		require.NoError(t, err)
		intent3, err := parseIntentFixtures(intentFixture3)
		require.NoError(t, err)

		// Push
		err = store.Intents().Push(
			intent1.Intent, intent1.BoardingInputs, intent1.CosignersPublicKeys,
		)
		require.NoError(t, err)

		err = store.Intents().Push(
			intent1.Intent, intent1.BoardingInputs, intent1.CosignersPublicKeys,
		)
		require.Contains(t, err.Error(), "duplicated intent")

		err = store.Intents().Push(
			intent3.Intent, intent3.BoardingInputs, intent3.CosignersPublicKeys,
		)
		require.Contains(t, err.Error(), "duplicated input")

		err = store.Intents().Push(
			intent2.Intent, intent2.BoardingInputs, intent2.CosignersPublicKeys,
		)
		require.NoError(t, err)

		// View
		got, ok := store.Intents().View(intent1.Intent.Id)
		require.True(t, ok)
		require.Equal(t, intent1.Intent.Id, got.Id)
		_, ok = store.Intents().View("nonexistent")
		require.False(t, ok)

		// ViewAll
		all, err := store.Intents().ViewAll(
			[]string{intent1.Intent.Id, intent2.Intent.Id, "nonexistent"},
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
		found, _ := store.Intents().IncludesAny([]domain.Outpoint{})
		require.False(t, found)

		found, _ = store.Intents().IncludesAny([]domain.Outpoint{{
			Txid: "24de502601c21cf7b227c0667ffe1175841cdd4f6e5b20d3063387333d0b10da", VOut: 0,
		}})
		require.True(t, found)

		// Len
		ln := store.Intents().Len()
		require.EqualValues(t, 2, ln)

		// Pop
		popped := store.Intents().Pop(2)
		require.Len(t, popped, 2)

		ln = store.Intents().Len()
		require.Zero(t, ln)

		popped = store.Intents().Pop(100)
		require.Empty(t, popped)

		// Delete
		err = store.Intents().Delete([]string{intent1.Intent.Id})
		require.NoError(t, err)

		// Delete non-existent
		err = store.Intents().Delete([]string{"doesnotexist"})
		require.NoError(t, err)

		// DeleteAll
		err = store.Intents().DeleteAll()
		require.NoError(t, err)

		// Make sure DeleteVtxos doesn't panic
		store.Intents().DeleteVtxos()
	})

	t.Run("ForfeitTxsStore", func(t *testing.T) {
		connectors, intents, err := parseForfeitTxsFixture(connectorsJSON, intentsJSON)
		require.NoError(t, err)

		// Init
		err = store.ForfeitTxs().Init(connectors, intents)
		require.NoError(t, err)

		// Sign
		err = store.ForfeitTxs().Sign([]string{tx1, tx2, tx3, tx4})
		require.NoError(t, err)

		// AllSigned
		require.True(t, store.ForfeitTxs().AllSigned())

		require.True(t, store.ForfeitTxs().Len() == 4)

		forfeits, err := store.ForfeitTxs().Pop()
		require.NoError(t, err)
		require.Equal(t, 4, len(forfeits))

		// Len
		require.True(t, store.ForfeitTxs().Len() == 0)

		store.ForfeitTxs().Reset()

		require.Equal(t, 0, store.ForfeitTxs().Len())
	})

	t.Run("OffChainTxStore", func(t *testing.T) {
		tx, err := parseOffchainTxFixture(offchainTxJSON)
		require.NoError(t, err)

		// Add
		store.OffchainTxs().Add(tx)

		// Get
		_, exists := store.OffchainTxs().Get("nonexistent")
		require.False(t, exists)

		// Get
		_, exists = store.OffchainTxs().Get(tx.ArkTxid)
		require.True(t, exists)

		// Includes
		outpointJSON := `{"Txid":"fefcc1d90510aa15a77b3bac88a745f7cc58a02a1d4ebe631901bff7f327c51a","VOut":0}`
		var outpoint domain.Outpoint
		err = json.Unmarshal([]byte(outpointJSON), &outpoint)
		require.NoError(t, err)
		exists = store.OffchainTxs().Includes(outpoint)
		require.True(t, exists)

		// Remove
		store.OffchainTxs().Remove(tx.ArkTxid)

		// Get
		_, exists = store.OffchainTxs().Get(tx.ArkTxid)
		require.False(t, exists)
	})

	t.Run("CurrentRoundStore", func(t *testing.T) {
		r := domain.NewRound()

		// Upsert
		err := store.CurrentRound().Upsert(func(_ *domain.Round) *domain.Round { return r })
		require.NoError(t, err)

		// Get
		got := store.CurrentRound().Get()
		require.Equal(t, r.Id, got.Id)

		// Fail
		events := store.CurrentRound().Fail(fmt.Errorf("fail"))
		require.Len(t, events, 1)
	})

	t.Run("ConfirmationSessionsStore", func(t *testing.T) {
		hashes := [][32]byte{h1, h2}

		// Init
		store.ConfirmationSessions().Init(hashes)

		// IsInit
		require.True(t, store.ConfirmationSessions().Initialized())

		doneCh := make(chan struct{})
		sessionCompleteCh := store.ConfirmationSessions().SessionCompleted()
		go func() {
			<-sessionCompleteCh
			doneCh <- struct{}{}
		}()

		// Confirm
		go func() {
			time.Sleep(1 * time.Second)
			err := store.ConfirmationSessions().Confirm(
				"fdbc502adf42a40dc7c0b2d3b50b9c0b01f9c386dc9bef5233bc9f39acdf48ae",
			)
			require.NoError(t, err)

			err = store.ConfirmationSessions().Confirm(
				"340f30bc56d8de1364120aaf8734f684a28084bc9fbb17029584378d1422beff",
			)
			require.NoError(t, err)
		}()

		select {
		case <-time.After(5 * time.Second):
			require.Fail(t, "Confirmation session not completed")
		case <-doneCh:
		}

		// Get
		got := store.ConfirmationSessions().Get()
		require.Equal(t, 2, len(got.IntentsHashes))
		require.Equal(t, 2, got.NumIntents)

		// Reset
		store.ConfirmationSessions().Reset()

		// IsInit
		require.False(t, store.ConfirmationSessions().Initialized())
	})

	t.Run("TreeSigningSessionsStore", func(t *testing.T) {
		// New
		var uniqueSigners map[string]struct{}
		err := json.Unmarshal([]byte(uniqueSignersJSON), &uniqueSigners)
		require.NoError(t, err)
		sigSession := store.TreeSigingSessions().New(roundId, uniqueSigners)
		require.Equal(t, 2+1, sigSession.NbCosigners)

		noncesCollectedCh := store.TreeSigingSessions().NoncesCollected(roundId)
		signaturesCollectedCh := store.TreeSigingSessions().SignaturesCollected(roundId)
		doneCh := make(chan struct{})
		go func() {
			<-noncesCollectedCh
			<-signaturesCollectedCh
			doneCh <- struct{}{}
		}()

		go func() {
			ctx := context.Background()
			pubkey1 := "021f5b9ff8f25ff7b8984f444abb75621267251cbba76f32d12bf6b4da3b3a7096"
			pubkey2 := "039f2214798b94cd517ccd561e739ebb73cecacdc41b387beb460dda097c2b7c67"
			// Collect nonces
			var nonce1, nonce2 tree.TreeNonces
			err = json.Unmarshal([]byte(n1), &nonce1)
			require.NoError(t, err)
			err = json.Unmarshal([]byte(n2), &nonce2)
			require.NoError(t, err)
			err = store.TreeSigingSessions().AddNonces(ctx, roundId, pubkey1, nonce1)
			require.NoError(t, err)
			err = store.TreeSigingSessions().AddNonces(ctx, roundId, pubkey2, nonce2)
			require.NoError(t, err)

			// Collect signatures
			sig1 := make(tree.TreePartialSigs)
			err = json.Unmarshal([]byte(s1), &sig1)
			require.NoError(t, err)
			sig2 := make(tree.TreePartialSigs)
			err = json.Unmarshal([]byte(s2), &sig2)
			require.NoError(t, err)

			err = store.TreeSigingSessions().AddSignatures(ctx, roundId, pubkey1, sig1)
			require.NoError(t, err)

			err = store.TreeSigingSessions().AddSignatures(ctx, roundId, pubkey2, sig2)
			require.NoError(t, err)
		}()

		select {
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		case <-doneCh:
		}

		// Delete
		store.TreeSigingSessions().Delete(roundId)

		// Get
		sigSession, exists := store.TreeSigingSessions().Get(roundId)
		require.False(t, exists)
		require.Nil(t, sigSession)
	})

	t.Run("BoardingInputsStore", func(t *testing.T) {
		store.BoardingInputs().Set(42)
		require.Equal(t, 42, store.BoardingInputs().Get())
		store.BoardingInputs().Set(0)
		require.Equal(t, 0, store.BoardingInputs().Get())
	})
}

type intentPushFixture struct {
	Intent              domain.Intent         `json:"intent"`
	BoardingInputs      []ports.BoardingInput `json:"boardingInputs"`
	CosignersPublicKeys []string              `json:"cosignerPubkeys"`
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
	mock.Mock
}

func (m *mockedTxBuilder) VerifyForfeitTxs(
	vtxos []domain.Vtxo, connectors tree.FlatTxTree, txs []string,
) (valid map[domain.Outpoint]ports.ValidForfeitTx, err error) {
	args := m.Called(vtxos, connectors, txs)
	res0 := args.Get(0).(map[domain.Outpoint]ports.ValidForfeitTx)
	return res0, args.Error(1)
}

func (m *mockedTxBuilder) BuildCommitmentTx(
	signerPubkey *btcec.PublicKey, intents domain.Intents,
	boardingInputs []ports.BoardingInput, connectorAddresses []string, cosignerPubkeys [][]string,
) (
	commitmentTx string, vtxoTree *tree.TxTree,
	connectorAddress string, connectors *tree.TxTree, err error,
) {
	args := m.Called(signerPubkey, intents, boardingInputs, connectorAddresses, cosignerPubkeys)
	res0 := args.Get(0).(string)
	res1 := args.Get(1).(*tree.TxTree)
	res2 := args.Get(2).(string)
	res3 := args.Get(3).(*tree.TxTree)
	return res0, res1, res2, res3, args.Error(4)
}

func (m *mockedTxBuilder) BuildSweepTx(
	inputs []ports.SweepableOutput,
) (txid string, signedSweepTx string, err error) {
	args := m.Called(inputs)
	res0 := args.Get(0).(string)
	res1 := args.Get(1).(string)
	return res0, res1, args.Error(2)
}

func (m *mockedTxBuilder) GetSweepableBatchOutputs(
	vtxoTree *tree.TxTree,
) (vtxoTreeExpiry *arklib.RelativeLocktime, sweepInput ports.SweepableOutput, err error) {
	args := m.Called(vtxoTree)
	res0 := args.Get(0).(*arklib.RelativeLocktime)
	res1 := args.Get(1).(ports.SweepableOutput)
	return res0, res1, args.Error(2)
}

func (m *mockedTxBuilder) FinalizeAndExtract(tx string) (txhex string, err error) {
	args := m.Called(tx)
	res0 := args.Get(0).(string)
	return res0, args.Error(1)
}

func (m *mockedTxBuilder) VerifyTapscriptPartialSigs(
	tx string,
) (valid bool, ptx *psbt.Packet, err error) {
	args := m.Called(tx)
	res0 := args.Get(0).(bool)
	res1 := args.Get(1).(*psbt.Packet)
	return res0, res1, args.Error(2)
}

func (m *mockedTxBuilder) VerifyAndCombinePartialTx(dest string, src string) (string, error) {
	args := m.Called(dest, src)
	res0 := args.Get(0).(string)
	return res0, args.Error(1)
}

func (m *mockedTxBuilder) CountSignedTaprootInputs(tx string) (int, error) {
	args := m.Called(tx)
	res0 := args.Get(0).(int)
	return res0, args.Error(1)
}

func (m *mockedTxBuilder) GetTxid(tx string) (string, error) {
	args := m.Called(tx)
	res0 := args.Get(0).(string)
	return res0, args.Error(1)
}
