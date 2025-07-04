package txbuilder_test

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/mock"
)

type mockedWallet struct {
	mock.Mock
}

func (m *mockedWallet) GetReadyUpdate(ctx context.Context) (<-chan struct{}, error) {
	args := m.Called(ctx)

	var res chan struct{}
	if a := args.Get(0); a != nil {
		res = a.(chan struct{})
	}
	return res, args.Error(1)
}

func (m *mockedWallet) GenSeed(ctx context.Context) (string, error) {
	args := m.Called(ctx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) Create(ctx context.Context, seed, password string) error {
	args := m.Called(ctx, seed, password)
	return args.Error(0)
}

func (m *mockedWallet) Restore(ctx context.Context, seed, password string) error {
	args := m.Called(ctx, seed, password)
	return args.Error(0)
}

func (m *mockedWallet) Unlock(ctx context.Context, password string) error {
	args := m.Called(ctx, password)
	return args.Error(0)
}

func (m *mockedWallet) Lock(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockedWallet) BroadcastTransaction(ctx context.Context, txs ...string) (string, error) {
	args := m.Called(ctx, txs)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) Close() {
	m.Called()
}

func (m *mockedWallet) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	args := m.Called(ctx, num)

	var res []string
	if a := args.Get(0); a != nil {
		res = a.([]string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) DeriveConnectorAddress(ctx context.Context) (string, error) {
	args := m.Called(ctx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) GetPubkey(ctx context.Context) (*btcec.PublicKey, error) {
	args := m.Called(ctx)

	var res *btcec.PublicKey
	if a := args.Get(0); a != nil {
		res = a.(*btcec.PublicKey)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) GetNetwork(ctx context.Context) (*arklib.Network, error) {
	args := m.Called(ctx)

	var res *arklib.Network
	if a := args.Get(0); a != nil {
		res = a.(*arklib.Network)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) SignTransaction(
	ctx context.Context, tx string, extractRawTx bool,
) (string, error) {
	args := m.Called(ctx, tx, extractRawTx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) Status(ctx context.Context) (ports.WalletStatus, error) {
	args := m.Called(ctx)

	var res ports.WalletStatus
	if a := args.Get(0); a != nil {
		res = a.(ports.WalletStatus)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) SelectUtxos(
	ctx context.Context, asset string, amount uint64, confirmedOnly bool,
) ([]ports.TxInput, uint64, error) {
	args := m.Called(ctx, asset, amount, confirmedOnly)

	var res0 func() []ports.TxInput
	if a := args.Get(0); a != nil {
		res0 = a.(func() []ports.TxInput)
	}
	var res1 uint64
	if a := args.Get(1); a != nil {
		res1 = a.(uint64)
	}
	return res0(), res1, args.Error(2)
}

func (m *mockedWallet) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	args := m.Called(ctx, pset)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) FeeRate(ctx context.Context) (uint64, error) {
	args := m.Called(ctx)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}

	return res, nil
}

func (m *mockedWallet) GetForfeitAddress(ctx context.Context) (string, error) {
	args := m.Called(ctx)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) GetDustAmount(ctx context.Context) (uint64, error) {
	args := m.Called(ctx)

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) IsTransactionConfirmed(
	ctx context.Context, txid string,
) (bool, int64, int64, error) {
	args := m.Called(ctx, txid)

	var res bool
	if a := args.Get(0); a != nil {
		res = a.(bool)
	}

	var height int64
	if h := args.Get(1); h != nil {
		height = h.(int64)
	}

	var blocktime int64
	if b := args.Get(1); b != nil {
		blocktime = b.(int64)
	}

	return res, height, blocktime, args.Error(2)
}

func (m *mockedWallet) SignTransactionTapscript(
	ctx context.Context, tx string, inputIndexes []int,
) (string, error) {
	args := m.Called(ctx, tx, inputIndexes)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) WatchScripts(
	ctx context.Context, scripts []string,
) error {
	args := m.Called(ctx, scripts)
	return args.Error(0)
}

func (m *mockedWallet) UnwatchScripts(
	ctx context.Context, scripts []string,
) error {
	args := m.Called(ctx, scripts)
	return args.Error(0)
}

func (m *mockedWallet) GetNotificationChannel(
	ctx context.Context,
) <-chan map[string][]ports.VtxoWithValue {
	args := m.Called(ctx)

	var res <-chan map[string][]ports.VtxoWithValue
	if a := args.Get(0); a != nil {
		res = a.(<-chan map[string][]ports.VtxoWithValue)
	}
	return res
}

func (m *mockedWallet) ListConnectorUtxos(
	ctx context.Context, addr string,
) ([]ports.TxInput, error) {
	args := m.Called(ctx, addr)

	var res []ports.TxInput
	if a := args.Get(0); a != nil {
		res = a.([]ports.TxInput)
	}

	return res, args.Error(1)
}

func (m *mockedWallet) LockConnectorUtxos(ctx context.Context, utxos []domain.Outpoint) error {
	args := m.Called(ctx, utxos)
	return args.Error(0)
}

func (m *mockedWallet) WaitForSync(ctx context.Context, txid string) error {
	args := m.Called(ctx, txid)
	return args.Error(0)
}

func (m *mockedWallet) GetTransaction(ctx context.Context, txid string) (string, error) {
	args := m.Called(ctx, txid)

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res, args.Error(1)
}

func (m *mockedWallet) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
	panic("not implemented")
}

func (m *mockedWallet) VerifyMessageSignature(
	ctx context.Context, message, signature []byte,
) (bool, error) {
	panic("not implemented")
}

func (m *mockedWallet) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	panic("not implemented")
}

func (m *mockedWallet) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	panic("not implemented")
}

func (m *mockedWallet) GetCurrentBlockTime(ctx context.Context) (*ports.BlockTimestamp, error) {
	panic("not implemented")
}

func (m *mockedWallet) Withdraw(
	ctx context.Context, address string, amount uint64,
) (string, error) {
	panic("not implemented")
}

type mockedInput struct {
	mock.Mock
}

func (m *mockedInput) GetTxid() string {
	args := m.Called()

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}

	return res
}

func (m *mockedInput) GetIndex() uint32 {
	args := m.Called()

	var res uint32
	if a := args.Get(0); a != nil {
		res = a.(uint32)
	}
	return res
}

func (m *mockedInput) GetScript() string {
	args := m.Called()

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res
}

func (m *mockedInput) GetAsset() string {
	args := m.Called()

	var res string
	if a := args.Get(0); a != nil {
		res = a.(string)
	}
	return res
}

func (m *mockedInput) GetValue() uint64 {
	args := m.Called()

	var res uint64
	if a := args.Get(0); a != nil {
		res = a.(uint64)
	}
	return res
}
