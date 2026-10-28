package application

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txsigner"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestReactToFraudForfeitRetry(t *testing.T) {
	rejection := errors.New(`submitpackage failed: package_msg="transaction failed"; wtxid forfeit: mandatory-script-verify-flag-failed`)
	tests := []struct {
		name           string
		vtxoIndex      int
		broadcastErrs  []error
		signerErr      error
		invalidVtxo    bool
		wantBroadcasts int
		wantSigns      int
		wantErr        string
	}{
		{name: "accepted", wantBroadcasts: 1},
		{name: "rejected then accepted", broadcastErrs: []error{rejection}, wantBroadcasts: 2, wantSigns: 1},
		{name: "connector first", vtxoIndex: 1, broadcastErrs: []error{rejection}, wantBroadcasts: 2, wantSigns: 1},
		{name: "retry rejected", broadcastErrs: []error{rejection, rejection}, wantBroadcasts: 2, wantSigns: 1, wantErr: "failed to broadcast rebuilt forfeit tx"},
		{name: "unrelated failure", broadcastErrs: []error{errors.New("connection refused")}, wantBroadcasts: 1, wantErr: "connection refused"},
		{name: "rebuild fails", broadcastErrs: []error{rejection}, invalidVtxo: true, wantBroadcasts: 1, wantErr: "failed to rebuild forfeit tx"},
		{name: "signing fails", broadcastErrs: []error{rejection}, signerErr: errors.New("signer unavailable"), wantBroadcasts: 1, wantSigns: 1, wantErr: "signer unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFraudForfeitFixture(t, tt.vtxoIndex)
			f.wallet.broadcastErrs = tt.broadcastErrs
			f.signer.err = tt.signerErr
			if len(tt.broadcastErrs) == 0 {
				f.round.ForfeitTxs[0].Tx = f.signer.returnTx
			}
			if tt.invalidVtxo {
				f.vtxo.Amount++
			}

			err := f.service.reactToFraud(t.Context(), f.vtxo, newKeyedMutex())
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, f.wallet.broadcasts, tt.wantBroadcasts)
			require.Equal(t, tt.wantSigns, f.signer.calls)
			require.Equal(t, 1, f.wallet.coinSelections, "retry must reuse the fee-paying child")
			if tt.wantSigns > 0 {
				require.Equal(t, f.userSigned, f.signer.lastTx,
					"keep both users' signatures and the spending proof, dropping all operator signatures and other metadata")
			}
			if tt.wantBroadcasts == 2 {
				first := decodeForfeitBroadcast(t, f.wallet.broadcasts[0][0])
				retry := decodeForfeitBroadcast(t, f.wallet.broadcasts[1][0])
				require.Equal(t, first.TxHash(), retry.TxHash())
				require.NotEqual(t, first.WitnessHash(), retry.WitnessHash())
				require.Equal(t, f.wallet.broadcasts[0][1], f.wallet.broadcasts[1][1])
				prevouts, err := txutils.GetPrevOutputFetcher(f.packet)
				require.NoError(t, err)
				for i, in := range f.packet.Inputs {
					engine, err := txscript.NewEngine(
						in.WitnessUtxo.PkScript, retry, i, txscript.StandardVerifyFlags,
						nil, txscript.NewTxSigHashes(retry, prevouts), in.WitnessUtxo.Value, prevouts,
					)
					require.NoError(t, err)
					require.NoError(t, engine.Execute(), "rebuilt forfeit must have valid witnesses")
				}
			}
		})
	}
}

type fraudForfeitFixture struct {
	service    *service
	wallet     *fraudForfeitWallet
	signer     *fakeForfeitSigner
	vtxo       domain.Vtxo
	round      *domain.Round
	packet     *psbt.Packet
	userSigned string
}

// ponytail: use a conditional multisig here; the builder tests cover plain multisig.
func newFraudForfeitFixture(t *testing.T, vtxoIndex int) fraudForfeitFixture {
	t.Helper()
	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cosignerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	operatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	currentKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	connectorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	closure := &script.ConditionMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{
			userKey.PubKey(), cosignerKey.PubKey(), operatorKey.PubKey(),
		}},
		Condition: []byte{txscript.OP_DROP, txscript.OP_TRUE},
	}
	leafScript, err := closure.Script()
	require.NoError(t, err)
	leaf := txscript.NewBaseTapLeaf(leafScript)
	tapTree := txscript.AssembleTaprootScriptTree(leaf)
	root := tapTree.RootNode.TapHash()
	vtxoKey := txscript.ComputeTaprootOutputKey(script.UnspendableKey(), root[:])
	vtxoScript, err := script.P2TRScript(vtxoKey)
	require.NoError(t, err)
	controlBlock := tapTree.LeafMerkleProofs[0].ToControlBlock(script.UnspendableKey())
	controlBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)
	connectorScript, err := script.P2TRScript(txscript.ComputeTaprootKeyNoScript(connectorKey.PubKey()))
	require.NoError(t, err)
	connector, err := psbt.New(
		[]*wire.OutPoint{{Hash: chainhash.Hash{1}}}, []*wire.TxOut{wire.NewTxOut(330, connectorScript)},
		3, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	connectorB64, err := connector.B64Encode()
	require.NoError(t, err)
	vtxoHash := chainhash.Hash{2}
	vtxo := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: vtxoHash.String()}, Amount: 10_000,
		PubKey: hex.EncodeToString(schnorr.SerializePubKey(vtxoKey)), SettledBy: "commitment-txid",
	}
	forfeitAddress, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(connectorKey.PubKey().SerializeCompressed()), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	forfeitScript, err := txscript.PayToAddrScript(forfeitAddress)
	require.NoError(t, err)
	inputs := []*wire.OutPoint{{Hash: vtxoHash}, {Hash: connector.UnsignedTx.TxHash()}}
	prevouts := []*wire.TxOut{wire.NewTxOut(int64(vtxo.Amount), vtxoScript), connector.UnsignedTx.TxOut[0]}
	if vtxoIndex == 1 {
		inputs[0], inputs[1] = inputs[1], inputs[0]
		prevouts[0], prevouts[1] = prevouts[1], prevouts[0]
	}
	p, err := tree.BuildForfeitTx(inputs, []uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum}, prevouts, forfeitScript, 0)
	require.NoError(t, err)
	p.Inputs[vtxoIndex].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script: leafScript, ControlBlock: controlBytes, LeafVersion: txscript.BaseLeafVersion,
	}}
	require.NoError(t, txutils.SetArkPsbtField(p, vtxoIndex, txutils.ConditionWitnessField, wire.TxWitness{[]byte("proof")}))
	prevoutFetcher, err := txutils.GetPrevOutputFetcher(p)
	require.NoError(t, err)
	hashes := txscript.NewTxSigHashes(p.UnsignedTx, prevoutFetcher)
	var userSigned string
	var operatorSig *psbt.TaprootScriptSpendSig
	for _, key := range []*btcec.PrivateKey{userKey, cosignerKey, operatorKey} {
		if key == operatorKey {
			userSigned, err = p.B64Encode()
			require.NoError(t, err)
		}
		sig, err := txscript.RawTxInTapscriptSignature(
			p.UnsignedTx, hashes, vtxoIndex, int64(vtxo.Amount), vtxoScript, leaf, txscript.SigHashDefault, key,
		)
		require.NoError(t, err)
		leafHash := leaf.TapHash()
		spend := &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: schnorr.SerializePubKey(key.PubKey()), LeafHash: leafHash[:], Signature: sig,
		}
		p.Inputs[vtxoIndex].TaprootScriptSpendSig = append(p.Inputs[vtxoIndex].TaprootScriptSpendSig, spend)
		if key == operatorKey {
			operatorSig = spend
		}
	}
	connectorIndex := 1 - vtxoIndex
	p.Inputs[connectorIndex].TaprootKeySpendSig, err = txscript.RawTxInTaprootSignature(
		p.UnsignedTx, hashes, connectorIndex, 330, connectorScript, nil, txscript.SigHashDefault, connectorKey,
	)
	require.NoError(t, err)
	signed, err := p.B64Encode()
	require.NoError(t, err)

	// Corrupt the deprecated operator's signature and add the current key's
	// signature plus metadata that must never be passed back to the signer.
	operatorSig.Signature = make([]byte, 64)
	p.Inputs[vtxoIndex].TaprootScriptSpendSig = append(p.Inputs[vtxoIndex].TaprootScriptSpendSig, spendSig(currentKey.PubKey(), leafScript))
	poison := []*psbt.Unknown{{Key: []byte{0xfc, 0x01}, Value: []byte("poison")}}
	p.Unknowns = poison
	for i := range p.Inputs {
		p.Inputs[i].TaprootMerkleRoot = root[:]
		p.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(currentKey.PubKey())
		p.Inputs[i].SighashType = txscript.SigHashAll
		p.Inputs[i].Unknowns = append(p.Inputs[i].Unknowns, poison...)
	}
	for i := range p.Outputs {
		p.Outputs[i].Unknowns = poison
	}
	stored, err := p.B64Encode()
	require.NoError(t, err)
	require.True(t, domain.ForfeitTxReadyToBroadcast(p), "invalid tapscript signatures pass the presence check")

	wallet := &fraudForfeitWallet{t: t, key: connectorKey, script: connectorScript}
	signer := &fakeForfeitSigner{returnTx: signed}
	round := &domain.Round{
		Connectors: tree.FlatTxTree{{Txid: connector.UnsignedTx.TxID(), Tx: connectorB64}},
		ForfeitTxs: []domain.ForfeitTx{{Txid: p.UnsignedTx.TxID(), Tx: stored}},
	}
	wallet.On("GetTransaction", mock.Anything, connector.UnsignedTx.TxID()).Return("confirmed", nil)
	rounds := &mockedRoundRepo{}
	rounds.On("GetRoundWithCommitmentTxid", mock.Anything, vtxo.SettledBy).Return(round, nil)
	// The confirmation of the forfeit tx is recorded on the utxo tracking the unrolled vtxo.
	repos := &mockedRepoManager{utxos: newFakeUtxoRepo()}
	repos.On("Rounds").Return(rounds)
	svc := &service{
		wallet: wallet, signer: signer, repoManager: repos,
		builder: txbuilder.NewTxBuilder(wallet, signer, arklib.BitcoinRegTest),
		cache: testLiveStore{settings: testSettingsStore{settings: &ports.Settings{
			SignerPubkey:            currentKey.PubKey(),
			DeprecatedSignerPubkeys: []ports.DeprecatedSignerPubkey{{PubKey: operatorKey.PubKey()}},
		}}},
	}
	return fraudForfeitFixture{service: svc, wallet: wallet, signer: signer, vtxo: vtxo, round: round, packet: p, userSigned: userSigned}
}

type fraudForfeitWallet struct {
	mockWalletService
	t              *testing.T
	key            *btcec.PrivateKey
	script         []byte
	broadcasts     [][]string
	broadcastErrs  []error
	coinSelections int
}

func (w *fraudForfeitWallet) GetForfeitPubkey(context.Context) (*btcec.PublicKey, error) {
	return w.key.PubKey(), nil
}

func (w *fraudForfeitWallet) GetCurrentBlockTime(context.Context) (*ports.BlockTimestamp, error) {
	return &ports.BlockTimestamp{Height: 100}, nil
}

// GetNetwork and IsTransactionConfirmed serve the wait for the confirmation of the forfeit tx
// that follows its broadcast, confirming anything right away.
func (w *fraudForfeitWallet) GetNetwork(context.Context) (*arklib.Network, error) {
	return &arklib.BitcoinRegTest, nil
}

func (w *fraudForfeitWallet) IsTransactionConfirmed(
	context.Context, string,
) (bool, *ports.BlockTimestamp, error) {
	return true, &ports.BlockTimestamp{Height: 101, Time: time.Now().Unix()}, nil
}

func (w *fraudForfeitWallet) SelectUtxos(context.Context, string, uint64, bool) ([]ports.TxInput, uint64, error) {
	w.coinSelections++
	return []ports.TxInput{{Txid: chainhash.Hash{3}.String(), Value: 100_000}}, 0, nil
}

func (w *fraudForfeitWallet) DeriveAddresses(context.Context, int) ([]string, error) {
	addr, err := address.NewAddressTaproot(w.script[2:], &chaincfg.RegressionNetParams)
	if err != nil {
		return nil, err
	}
	return []string{addr.String()}, nil
}

func (w *fraudForfeitWallet) SignTransaction(
	_ context.Context, tx string, extractRawTx bool,
) (string, error) {
	p, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	require.NoError(w.t, err)
	// The forfeit tx reaches the wallet with its connector input already signed.
	if extractRawTx {
		return txsigner.ExtractFinalizedTx(p)
	}
	p.Inputs[1].WitnessUtxo = wire.NewTxOut(100_000, w.script)
	prevouts, err := txutils.GetPrevOutputFetcher(p)
	require.NoError(w.t, err)
	p.Inputs[1].TaprootKeySpendSig, err = txscript.RawTxInTaprootSignature(
		p.UnsignedTx, txscript.NewTxSigHashes(p.UnsignedTx, prevouts), 1, 100_000, w.script, nil, txscript.SigHashDefault, w.key,
	)
	require.NoError(w.t, err)
	return p.B64Encode()
}

func (w *fraudForfeitWallet) BroadcastTransaction(_ context.Context, txs ...string) (string, error) {
	w.broadcasts = append(w.broadcasts, txs)
	if len(w.broadcasts) <= len(w.broadcastErrs) {
		return "", w.broadcastErrs[len(w.broadcasts)-1]
	}
	return "accepted", nil
}

func decodeForfeitBroadcast(t *testing.T, txHex string) *wire.MsgTx {
	t.Helper()
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))))
	return &tx
}
