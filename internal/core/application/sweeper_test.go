package application

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/require"
)

// fakeWallet is a distinct, comparable ports.WalletService identity. Only its
// pointer identity matters for the fallback-iteration tests.
type fakeWallet struct {
	ports.WalletService
	name string
}

// fakeSweepBuilder implements just the two sweep methods of ports.TxBuilder that
// buildAndSignSweepTx uses. SignSweepTx succeeds only for goodWallet, recording the
// order in which wallets are tried.
type fakeSweepBuilder struct {
	ports.TxBuilder
	buildErr   error
	unsignedTx string
	txid       string
	goodWallet ports.WalletService
	signCalls  []ports.WalletService
}

func (b *fakeSweepBuilder) BuildSweepTx(inputs []ports.TxInput) (string, string, error) {
	if b.buildErr != nil {
		return "", "", b.buildErr
	}
	return b.unsignedTx, b.txid, nil
}

func (b *fakeSweepBuilder) SignSweepTx(
	wallet ports.WalletService, unsignedTx string,
) (string, error) {
	b.signCalls = append(b.signCalls, wallet)
	if b.goodWallet != nil && wallet == b.goodWallet {
		return "signed:" + unsignedTx, nil
	}
	return "", fmt.Errorf("wallet %v cannot sign", wallet)
}

func TestBuildAndSignSweepTx(t *testing.T) {
	inputs := []ports.TxInput{{Txid: "aa", Index: 0}}
	primary := &fakeWallet{name: "primary"}
	fb1 := &fakeWallet{name: "fb1"}
	fb2 := &fakeWallet{name: "fb2"}
	wallets := []ports.WalletService{primary, fb1, fb2}

	t.Run("primary signs, fallbacks not tried", func(t *testing.T) {
		b := &fakeSweepBuilder{unsignedTx: "unsigned", txid: "txid123", goodWallet: primary}

		txid, signed, err := buildAndSignSweepTx(b, wallets, inputs)
		require.NoError(t, err)
		require.Equal(t, "txid123", txid)
		require.Equal(t, "signed:unsigned", signed)
		require.Equal(t, []ports.WalletService{primary}, b.signCalls)
	})

	t.Run("falls back to a later wallet in order", func(t *testing.T) {
		b := &fakeSweepBuilder{unsignedTx: "unsigned", txid: "txid123", goodWallet: fb2}

		txid, signed, err := buildAndSignSweepTx(b, wallets, inputs)
		require.NoError(t, err)
		require.Equal(t, "txid123", txid)
		require.Equal(t, "signed:unsigned", signed)
		require.Equal(t, []ports.WalletService{primary, fb1, fb2}, b.signCalls)
	})

	t.Run("no wallet can sign returns aggregated error naming each wallet", func(t *testing.T) {
		b := &fakeSweepBuilder{unsignedTx: "unsigned", txid: "txid123"}

		txid, signed, err := buildAndSignSweepTx(b, wallets, inputs)
		require.Error(t, err)
		require.Empty(t, txid)
		require.Empty(t, signed)
		require.Contains(t, err.Error(), "no wallet could sign sweep tx txid123")
		require.Contains(t, err.Error(), "wallet[0]")
		require.Contains(t, err.Error(), "wallet[2]")
		require.Len(t, b.signCalls, 3)
	})

	t.Run("no signing wallets configured", func(t *testing.T) {
		b := &fakeSweepBuilder{unsignedTx: "unsigned", txid: "txid123"}

		_, _, err := buildAndSignSweepTx(b, nil, inputs)
		require.ErrorContains(t, err, "no signing wallets configured for sweep tx txid123")
		require.Empty(t, b.signCalls)
	})

	t.Run("build error short-circuits before signing", func(t *testing.T) {
		b := &fakeSweepBuilder{buildErr: fmt.Errorf("boom")}

		_, _, err := buildAndSignSweepTx(b, wallets, inputs)
		require.ErrorContains(t, err, "boom")
		require.Empty(t, b.signCalls)
	})
}
