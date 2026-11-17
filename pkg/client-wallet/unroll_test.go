package wallet_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	"github.com/arkade-os/arkd/pkg/client-wallet/identity"
	identityinmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/store/inmemory"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

const (
	testPassword = "password"
	// testTxid is the txid of the boarding utxo served by the stub explorer.
	testTxid = "0000000000000000000000000000000000000000000000000000000000000001"
	// testBoardingAmount is the amount of the boarding utxo served by the stub explorer.
	testBoardingAmount = 100_000
)

var (
	testNetwork       = arklib.BitcoinRegTest
	boardingExitDelay = arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	// expiredBlockTime confirms the boarding utxo early enough for its exit path to be spendable.
	expiredBlockTime = time.Now().Add(-30 * 24 * time.Hour).Unix()
	errBroadcast     = errors.New("tx rejected by the node")
)

func TestWithdrawFromAllExpiredBoardings(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		receiver := newTestOnchainAddress(t)

		testCases := []struct {
			name             string
			opts             []wallet.UnrollOption
			expectedReceiver string
		}{
			{
				name:             "with receiver",
				opts:             []wallet.UnrollOption{wallet.WithReceiver(receiver)},
				expectedReceiver: receiver,
			},
			{
				name: "default receiver",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				w, explorer := newTestWallet(t, 0, expiredBlockTime)

				txid, err := w.WithdrawFromAllExpiredBoardings(t.Context(), tc.opts...)
				require.NoError(t, err)

				expectedReceiver := tc.expectedReceiver
				if len(expectedReceiver) <= 0 {
					onchainAddrs, _, _, _, err := w.GetAddresses(t.Context())
					require.NoError(t, err)
					expectedReceiver = onchainAddrs[0]
				}
				requireSweepBroadcast(t, explorer, txid, expectedReceiver)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name          string
			blockTime     int64
			opts          []wallet.UnrollOption
			broadcastErr  error
			expectedError string
		}{
			{
				name:          "boarding utxo not expired",
				blockTime:     time.Now().Unix(),
				expectedError: "no expired boarding funds available",
			},
			{
				name:          "receiver not onchain",
				blockTime:     expiredBlockTime,
				opts:          []wallet.UnrollOption{wallet.WithReceiver("invalid")},
				expectedError: "invalid receiver address",
			},
			{
				name:          "broadcast fails",
				blockTime:     expiredBlockTime,
				broadcastErr:  errBroadcast,
				expectedError: errBroadcast.Error(),
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				w, explorer := newTestWallet(t, 0, tc.blockTime)
				explorer.broadcastErr = tc.broadcastErr

				txid, err := w.WithdrawFromAllExpiredBoardings(t.Context(), tc.opts...)
				require.ErrorContains(t, err, tc.expectedError)
				require.Empty(t, txid)
				require.Empty(t, explorer.broadcasts)
			})
		}
	})
}

func TestOnboardAgainAllExpiredBoardings(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		w, explorer := newTestWallet(t, -1, expiredBlockTime)

		txid, err := w.OnboardAgainAllExpiredBoardings(t.Context())
		require.NoError(t, err)

		requireSweepBroadcast(t, explorer, txid, explorer.boardingAddr)
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name          string
			utxoMaxAmount int64
			blockTime     int64
			broadcastErr  error
			expectedError string
		}{
			{
				name:          "boarding disabled by the server",
				utxoMaxAmount: 0,
				blockTime:     expiredBlockTime,
				expectedError: "operation not allowed by the server",
			},
			{
				name:          "boarding utxo not expired",
				utxoMaxAmount: -1,
				blockTime:     time.Now().Unix(),
				expectedError: "no expired boarding funds available",
			},
			{
				name:          "broadcast fails",
				utxoMaxAmount: -1,
				blockTime:     expiredBlockTime,
				broadcastErr:  errBroadcast,
				expectedError: errBroadcast.Error(),
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				w, explorer := newTestWallet(t, tc.utxoMaxAmount, tc.blockTime)
				explorer.broadcastErr = tc.broadcastErr

				txid, err := w.OnboardAgainAllExpiredBoardings(t.Context())
				require.ErrorContains(t, err, tc.expectedError)
				require.Empty(t, txid)
				require.Empty(t, explorer.broadcasts)
			})
		}
	})
}

// stubExplorer serves a single boarding utxo, a fixed fee rate and records the broadcast txs,
// or rejects them with broadcastErr when set.
// No other explorer method is expected to be called by the tests.
type stubExplorer struct {
	clientlib.Explorer
	boardingAddr string
	utxo         clientlib.ExplorerUtxo
	broadcastErr error
	broadcasts   []*wire.MsgTx
}

func (e *stubExplorer) GetUtxos(addresses []string) ([]clientlib.ExplorerUtxo, error) {
	if !slices.Contains(addresses, e.boardingAddr) {
		return nil, nil
	}
	return []clientlib.ExplorerUtxo{e.utxo}, nil
}

func (e *stubExplorer) GetFeeRate() (float64, error) {
	return 1, nil
}

func (e *stubExplorer) Broadcast(txs ...string) (string, error) {
	if len(txs) == 0 {
		return "", fmt.Errorf("missing txs to broadcast")
	}
	if e.broadcastErr != nil {
		return "", e.broadcastErr
	}
	for _, txHex := range txs {
		raw, err := hex.DecodeString(txHex)
		if err != nil {
			return "", err
		}
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
			return "", err
		}
		e.broadcasts = append(e.broadcasts, tx)
	}
	return e.broadcasts[0].TxHash().String(), nil
}

// newTestWallet returns an unlocked wallet whose explorer serves a single boarding utxo
// confirmed at the given block time.
func newTestWallet(
	t *testing.T, utxoMaxAmount, blockTime int64,
) (wallet.Wallet, *stubExplorer) {
	t.Helper()

	identityStore, err := identityinmemorystore.NewStore()
	require.NoError(t, err)
	identitySvc, err := identity.NewIdentity(identityStore)
	require.NoError(t, err)
	_, err = identitySvc.Create(t.Context(), testNetwork, testPassword, "")
	require.NoError(t, err)
	_, err = identitySvc.Unlock(t.Context(), testPassword)
	require.NoError(t, err)

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	storeSvc, err := inmemorystore.NewStore()
	require.NoError(t, err)
	err = storeSvc.AddData(t.Context(), clientlib.ServerParams{
		ServerUrl:           "localhost:7070",
		SignerPubKey:        signerKey.PubKey(),
		Network:             testNetwork,
		UnilateralExitDelay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 512},
		BoardingExitDelay:   boardingExitDelay,
		Dust:                330,
		UtxoMaxAmount:       utxoMaxAmount,
	})
	require.NoError(t, err)

	explorer := &stubExplorer{}
	w, err := wallet.LoadWallet(
		storeSvc, wallet.WithIdentity(identitySvc), wallet.WithExplorer(explorer),
		wallet.WithoutFinalizePendingTxs(),
	)
	require.NoError(t, err)
	t.Cleanup(w.Stop)

	_, _, boardingAddrs, _, err := w.GetAddresses(t.Context())
	require.NoError(t, err)
	explorer.boardingAddr = boardingAddrs[0].Address
	explorer.utxo = clientlib.ExplorerUtxo{
		Txid:   testTxid,
		Vout:   0,
		Amount: testBoardingAmount,
		Script: hex.EncodeToString(outputScript(t, explorer.boardingAddr)),
		Status: clientlib.ConfirmedStatus{Confirmed: true, BlockTime: blockTime},
	}

	return w, explorer
}

// requireSweepBroadcast asserts that txid identifies the only broadcast tx and that the tx
// validly spends the boarding utxo to the given receiver.
func requireSweepBroadcast(t *testing.T, explorer *stubExplorer, txid, receiver string) {
	t.Helper()

	require.Len(t, explorer.broadcasts, 1)
	tx := explorer.broadcasts[0]
	require.Equal(t, tx.TxHash().String(), txid)

	require.Len(t, tx.TxIn, 1)
	require.Equal(t, testTxid, tx.TxIn[0].PreviousOutPoint.Hash.String())
	require.Equal(t, explorer.utxo.Vout, tx.TxIn[0].PreviousOutPoint.Index)

	require.Len(t, tx.TxOut, 1)
	require.Equal(t, outputScript(t, receiver), tx.TxOut[0].PkScript)
	require.Positive(t, tx.TxOut[0].Value)
	require.Less(t, tx.TxOut[0].Value, int64(testBoardingAmount))

	prevoutScript, err := hex.DecodeString(explorer.utxo.Script)
	require.NoError(t, err)
	prevoutFetcher := txscript.NewCannedPrevOutputFetcher(prevoutScript, testBoardingAmount)
	engine, err := txscript.NewEngine(
		prevoutScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, prevoutFetcher), testBoardingAmount, prevoutFetcher,
	)
	require.NoError(t, err)
	require.NoError(t, engine.Execute())
}

func newTestOnchainAddress(t *testing.T) string {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	netParams := clientlib.ToBitcoinNetwork(testNetwork)
	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(key.PubKey())), &netParams,
	)
	require.NoError(t, err)
	return addr.EncodeAddress()
}

func outputScript(t *testing.T, addr string) []byte {
	t.Helper()

	netParams := clientlib.ToBitcoinNetwork(testNetwork)
	decoded, err := address.DecodeAddress(addr, &netParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(decoded)
	require.NoError(t, err)
	return pkScript
}
