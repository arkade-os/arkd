package e2e_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCosignOnchainTx(t *testing.T) {
	require.NoError(t, generateBlocks(1))

	// The plain path: a confirmed boarding utxo is spent to an arbitrary destination with
	// arkd's cosignature, arkd broadcasts the tx and the indexer tracks the outpoint through
	// to spent and confirmed. Along the way, the request is refused while the utxo is
	// unconfirmed, while the tx misses the owner signature, and once the utxo is spent.
	t.Run("cosign boarding utxo", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClientWallet(t)
		bob := setupClientWallet(t)
		indexer := alice.Indexer()

		_, _, aliceBoardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotNil(t, aliceBoardingAddr)
		require.NotEmpty(t, aliceBoardingAddr.Tapscripts)

		_, _, bobBoardingAddr, err := bob.Receive(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBoardingAddr)
		require.NotEmpty(t, bobBoardingAddr.Tapscripts)

		rawScript, err := bobBoardingAddr.RawScript()
		require.NoError(t, err)
		tapkey, _, err := rawScript.TapTree()
		require.NoError(t, err)
		require.NotNil(t, tapkey)
		destScript, err := script.P2TRScript(tapkey)
		require.NoError(t, err)
		require.NotEmpty(t, destScript)
		destAddr := bobBoardingAddr.Address

		// Fund the boarding address with unconfirmed funds.
		sendOnchainAndWait(t, aliceBoardingAddr.Address, 0.00021)

		utxos := waitForOnchainUtxos(t, aliceBoardingAddr.Address, 1)
		require.Len(t, utxos, 1)
		utxo := utxos[0]

		// Build and sign a tx that spends the boarding utxo and sends it to a random destination
		// and pays 500 sats in network fees.
		ptx := onchainSpendPacket(t, utxo, aliceBoardingAddr.Tapscripts, destScript, 20500)
		unsignedTx, err := ptx.B64Encode()
		require.NoError(t, err)

		signedTx, err := alice.SignTransaction(ctx, unsignedTx)
		require.NoError(t, err)

		// Submit a request providing the unsigned tx to ensure it's rejected.
		resp, err := cosignOnchainTx(ctx, unsignedTx)
		require.Nil(t, resp)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing signatures for input")

		// Ensure the indexer doesn't track the utxo yet.
		utxoResp, err := indexer.GetUtxos(
			ctx, clientlib.WithOutpoints([]clientlib.Outpoint{{
				Txid: utxo.Txid,
				VOut: utxo.Vout,
			}}),
		)
		require.NoError(t, err)
		require.NotNil(t, utxoResp)
		require.Empty(t, utxoResp.Utxos)

		// Finally, submit the signed transaction, spending the still unconfirmed utxo, and verify
		// it's broadcasted.
		resp, err = cosignOnchainTx(ctx, signedTx)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotEmpty(t, resp.GetTxid())

		noResp, err := cosignOnchainTx(ctx, signedTx)
		require.Nil(t, noResp)
		require.Error(t, err)
		require.ErrorContains(t, err, "already spent")

		require.Eventually(t, func() bool {
			found, err := testExplorer.GetUtxos([]string{destAddr})
			require.NoError(t, err)

			return len(found) > 0
		}, 10*time.Second, 100*time.Millisecond)

		// Ensure the indexer now tracks the cosigned utxo.
		utxoResp, err = indexer.GetUtxos(
			ctx, clientlib.WithOutpoints([]clientlib.Outpoint{{
				Txid: utxo.Txid,
				VOut: utxo.Vout,
			}}),
		)
		require.NoError(t, err)
		require.NotNil(t, utxoResp)
		require.Len(t, utxoResp.Utxos, 1)
		gotUtxo := utxoResp.Utxos[0]
		require.Equal(t, utxo.Txid, gotUtxo.Txid)
		require.Equal(t, utxo.Vout, gotUtxo.VOut)
		require.Equal(t, utxo.Script, gotUtxo.Script)
		require.Equal(t, utxo.Amount, gotUtxo.Amount)
		require.Equal(t, resp.GetTxid(), gotUtxo.Spend.Txid)
		require.Zero(t, gotUtxo.Spend.ConfirmedAtHeight)
		require.True(t, gotUtxo.Spend.ConfirmedAtTime.IsZero())

		// Mine the funding tx and the cosigned one together.
		err = generateBlocks(1)
		require.NoError(t, err)

		// Ensure the indexer tracks the confirmation of the cosigned tx.
		require.Eventually(t, func() bool {
			resp, err := indexer.GetUtxos(
				ctx, clientlib.WithOutpoints([]clientlib.Outpoint{{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}}),
			)
			require.NoError(t, err)
			return len(resp.Utxos) > 0 && resp.Utxos[0].Spend.ConfirmedAtHeight > 0
		}, 10*time.Second, 100*time.Millisecond)
	})

	// An unrolled vtxo that is still unspent is cosigned like a boarding utxo. The spend is
	// recorded on the vtxo outpoint, so the vtxo can no longer rejoin a batch.
	t.Run("cosign unrolled vtxo", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClientWallet(t)
		bob := setupClientWallet(t)
		indexer := alice.Indexer()

		vtxo := faucetOffchain(t, alice, 0.00021)
		aliceOnchainAddr, aliceOffchainAddr, _, err := alice.Receive(ctx)
		require.NoError(t, err)
		// Onchain funds to cover the unroll fees.
		faucetOnchainAndWait(t, aliceOnchainAddr, 0.00001)

		_, _, bobBoardingAddr, err := bob.Receive(ctx)
		require.NoError(t, err)
		rawScript, err := bobBoardingAddr.RawScript()
		require.NoError(t, err)
		tapkey, _, err := rawScript.TapTree()
		require.NoError(t, err)
		destScript, err := script.P2TRScript(tapkey)
		require.NoError(t, err)

		txids, err := alice.Unroll(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, txids)
		require.NoError(t, generateBlocks(1))
		waitForUnrolledOnchainFunds(t, alice)

		waitUntil(t, indexerWait, "the vtxo to be reported unrolled",
			func(ctx context.Context) error {
				resp, err := indexer.GetVtxos(
					ctx, clientlib.WithOutpoints([]clientlib.Outpoint{vtxo.Outpoint}),
				)
				if err != nil {
					return err
				}
				if len(resp.Vtxos) != 1 || !resp.Vtxos[0].Unrolled {
					return fmt.Errorf("vtxo %s not reported unrolled yet", vtxo.Outpoint)
				}
				return nil
			},
		)

		utxo := clientlib.ExplorerUtxo{
			Txid: vtxo.Txid, Vout: vtxo.VOut, Amount: vtxo.Amount, Script: vtxo.Script,
		}
		ptx := onchainSpendPacket(
			t, utxo, aliceOffchainAddr.Tapscripts, destScript, int64(vtxo.Amount)-500,
		)
		unsignedTx, err := ptx.B64Encode()
		require.NoError(t, err)
		signedTx, err := alice.SignTransaction(ctx, unsignedTx)
		require.NoError(t, err)

		resp, err := cosignOnchainTx(ctx, signedTx)
		require.NoError(t, err)
		require.NotNil(t, resp)
		cosignTxid := resp.GetTxid()
		require.NotEmpty(t, cosignTxid)

		require.Eventually(t, func() bool {
			found, err := testExplorer.GetUtxos([]string{bobBoardingAddr.Address})
			require.NoError(t, err)
			return len(found) > 0
		}, 10*time.Second, 100*time.Millisecond)

		// The vtxo outpoint is recorded as a cosigned utxo with the vtxo's script and amount.
		utxoResp, err := indexer.GetUtxos(
			ctx, clientlib.WithOutpoints([]clientlib.Outpoint{vtxo.Outpoint}),
		)
		require.NoError(t, err)
		require.Len(t, utxoResp.Utxos, 1)
		require.Equal(t, vtxo.Script, utxoResp.Utxos[0].Script)
		require.Equal(t, vtxo.Amount, utxoResp.Utxos[0].Amount)
		require.Equal(t, cosignTxid, utxoResp.Utxos[0].Spend.Txid)

		cfgData, err := alice.GetConfigData(ctx)
		require.NoError(t, err)
		signingClosure, err := aliceOffchainAddr.CollaborativeClosure()
		require.NoError(t, err)
		_, err = batchSettleBounded(ctx, batchsession.SettleArgs{
			Client:       alice.Client(),
			ServerParams: *cfgData,
			SignTx:       alice.SignTransaction,
			BoardingUtxos: []clientlib.Utxo{{
				Outpoint:       vtxo.Outpoint,
				Amount:         vtxo.Amount,
				Tapscripts:     aliceOffchainAddr.Tapscripts,
				SigningClosure: signingClosure,
			}},
			ReceiverAddr: aliceOffchainAddr.Address,
		})
		require.ErrorContains(t, err, "already cosigned onchain")
	})

	// The case on-chain cosigning exists for. Funds sit at a boarding address whose
	// signer key arkd has since deprecated past its cutoff, so the owner cannot join a
	// batch: the batch path refuses the key. The exit leaf is theirs alone, but only once
	// BOARDING_EXIT_DELAY matures, three months by default. arkd still cosigns a direct
	// spend of the utxo to an arbitrary destination with the deprecated key.
	t.Run("cosign boarding utxo with signer past cutoff", func(t *testing.T) {
		const (
			oldSignerKey = "afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0"
			newSignerKey = "3333333333333333333333333333333333333333333333333333333333333333"
		)
		ctx := t.Context()

		// Restore the old signer key without deprecated keys for other integration tests.
		t.Cleanup(func() {
			require.NoError(t, recreateArkdSigner(oldSignerKey, ""))
		})

		alice := setupClientWallet(t)
		bob := setupClientWallet(t)
		indexer := alice.Indexer()

		// Alice's boarding address is derived before the rotation, so it embeds the old
		// signer key.
		_, _, aliceBoardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotNil(t, aliceBoardingAddr)
		require.NotEmpty(t, aliceBoardingAddr.Tapscripts)

		_, _, bobBoardingAddr, err := bob.Receive(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBoardingAddr)

		rawScript, err := bobBoardingAddr.RawScript()
		require.NoError(t, err)
		tapkey, _, err := rawScript.TapTree()
		require.NoError(t, err)
		destScript, err := script.P2TRScript(tapkey)
		require.NoError(t, err)
		destAddr := bobBoardingAddr.Address

		// Rotate: new key current, old key deprecated with a cutoff date in the past.
		expiredCutoff := time.Now().Add(-time.Hour).Unix()
		require.NoError(t, recreateArkdSigner(
			newSignerKey, fmt.Sprintf("%s:%d", oldSignerKey, expiredCutoff),
		))

		// Fund the boarding address only now, so the exit delay doesn't run while the
		// services restart, and confirm it.
		faucetOnchainAndWait(t, aliceBoardingAddr.Address, 0.00021)
		utxos := waitForOnchainUtxos(t, aliceBoardingAddr.Address, 1)
		require.Len(t, utxos, 1)
		utxo := utxos[0]

		// The batch path refuses the boarding utxo: its signer key is past the cutoff.
		_, err = settleBounded(ctx, alice)
		require.ErrorContains(t, err, "is a deprecated key since")

		// The cosign path doesn't, the deprecated key is still good to spend onchain.
		ptx := onchainSpendPacket(t, utxo, aliceBoardingAddr.Tapscripts, destScript, 20500)
		unsignedTx, err := ptx.B64Encode()
		require.NoError(t, err)
		signedTx, err := alice.SignTransaction(ctx, unsignedTx)
		require.NoError(t, err)

		resp, err := cosignOnchainTx(ctx, signedTx)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotEmpty(t, resp.GetTxid())

		require.Eventually(t, func() bool {
			found, err := testExplorer.GetUtxos([]string{destAddr})
			require.NoError(t, err)
			return len(found) > 0
		}, 10*time.Second, 100*time.Millisecond)

		// The indexer tracks the cosigned utxo, spent by the broadcast tx.
		utxoResp, err := indexer.GetUtxos(
			ctx, clientlib.WithOutpoints([]clientlib.Outpoint{{
				Txid: utxo.Txid,
				VOut: utxo.Vout,
			}}),
		)
		require.NoError(t, err)
		require.NotNil(t, utxoResp)
		require.Len(t, utxoResp.Utxos, 1)
		gotUtxo := utxoResp.Utxos[0]
		require.Equal(t, utxo.Txid, gotUtxo.Txid)
		require.Equal(t, utxo.Vout, gotUtxo.VOut)
		require.Equal(t, utxo.Script, gotUtxo.Script)
		require.Equal(t, utxo.Amount, gotUtxo.Amount)
		require.Equal(t, resp.GetTxid(), gotUtxo.Spend.Txid)
		require.Zero(t, gotUtxo.Spend.ConfirmedAtHeight)
		require.True(t, gotUtxo.Spend.ConfirmedAtTime.IsZero())

		require.NoError(t, generateBlocks(1))

		require.Eventually(t, func() bool {
			resp, err := indexer.GetUtxos(
				ctx, clientlib.WithOutpoints([]clientlib.Outpoint{{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}}),
			)
			require.NoError(t, err)
			return len(resp.Utxos) > 0 && resp.Utxos[0].Spend.ConfirmedAtHeight > 0
		}, 10*time.Second, 100*time.Millisecond)
	})

	// A boarding utxo spent by a batch is tracked like a cosigned one, and its spend is
	// confirmed once the commitment tx is.
	t.Run("boarding utxo spent by a batch", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClientWallet(t)
		indexer := alice.Indexer()

		_, _, boardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)
		faucetOnchainAndWait(t, boardingAddr.Address, 0.00021)
		utxos := waitForOnchainUtxos(t, boardingAddr.Address, 1)
		outpoints := []clientlib.Outpoint{{Txid: utxos[0].Txid, VOut: utxos[0].Vout}}

		res, err := settleBounded(ctx, alice)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			resp, err := indexer.GetUtxos(ctx, clientlib.WithOutpoints(outpoints))
			require.NoError(t, err)
			return len(resp.Utxos) == 1 && resp.Utxos[0].Spend.Txid == res.CommitmentTxid
		}, 10*time.Second, 100*time.Millisecond)

		require.NoError(t, generateBlocks(1))

		require.Eventually(t, func() bool {
			resp, err := indexer.GetUtxos(ctx, clientlib.WithOutpoints(outpoints))
			require.NoError(t, err)
			return len(resp.Utxos) == 1 && resp.Utxos[0].Spend.ConfirmedAtHeight > 0
		}, 10*time.Second, 100*time.Millisecond)
	})
}

// onchainSpendPacket builds the spend arkd is asked to cosign: the boarding
// utxo in, one arbitrary destination out, taking the cooperative leaf.
func onchainSpendPacket(
	t *testing.T, utxo clientlib.ExplorerUtxo, tapscripts []string,
	destScript []byte, amount int64,
) *psbt.Packet {
	t.Helper()

	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	require.NoError(t, err)

	// The only leaf arkd will cosign. The exit leaf needs no cosignature by
	// construction, which is why asking for one is refused.
	cooperative := vtxoScript.ForfeitClosures()[0]
	leafScript, err := cooperative.Script()
	require.NoError(t, err)

	tapKey, taprootTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	leafProof, err := taprootTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(leafScript).TapHash(),
	)
	require.NoError(t, err)

	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	hash, err := chainhash.NewHashFromStr(utxo.Txid)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(hash, utxo.Vout), nil, nil))
	tx.AddTxOut(wire.NewTxOut(amount, destScript))

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    int64(utxo.Amount),
		PkScript: pkScript,
	}
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: leafProof.ControlBlock,
			Script:       leafProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		},
	}

	// The whole tree, which the standard fields do not carry. arkd reads it from
	// here to check every leaf rather than only the one being spent.
	require.NoError(t, txutils.SetArkPsbtField(
		ptx, 0, txutils.VtxoTaprootTreeField, tapscripts,
	))

	return ptx
}

// cosignOnchainTx asks arkd to sign and broadcast signedTx.
func cosignOnchainTx(
	ctx context.Context, signedTx string,
) (*arkv1.CosignOnchainTxResponse, error) {
	conn, err := grpc.NewClient(
		serverUrl, grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	return arkv1.NewArkServiceClient(conn).CosignOnchainTx(
		ctx, &arkv1.CosignOnchainTxRequest{Tx: signedTx},
	)
}
