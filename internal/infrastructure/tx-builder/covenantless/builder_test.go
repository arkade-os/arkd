package txbuilder_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testingKey       = "020000000000000000000000000000000000000000000000000000000000000001"
	connectorAddress = "bc1py00yhcjpcj0k0sqra0etq0u3yy0purmspppsw0shyzyfe8c83tmq5h6kc2"
	forfeitPubkey    = "020000000000000000000000000000000000000000000000000000000000000002"
	changeAddress    = "bcrt1qhhq55mut9easvrncy4se8q6vg3crlug7yj4j56"
	minRelayFeeRate  = 3
)

var (
	wallet *mockedWallet
	pubkey *btcec.PublicKey

	vtxoTreeExpiry    = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1209344}
	boardingExitDelay = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}
)

func TestMain(m *testing.M) {
	wallet = &mockedWallet{}
	wallet.On("EstimateFees", mock.Anything, mock.Anything).
		Return(uint64(100), nil)
	wallet.On("SelectUtxos", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(randomInput, uint64(1000), nil)
	wallet.On("DeriveAddresses", mock.Anything, mock.Anything).
		Return([]string{changeAddress}, nil)
	wallet.On("DeriveConnectorAddress", mock.Anything).
		Return(connectorAddress, nil)
	wallet.On("GetDustAmount", mock.Anything).
		Return(uint64(1000), nil)
	wallet.On("GetForfeitPubkey", mock.Anything).
		Return(forfeitPubkey, nil)

	pubkeyBytes, _ := hex.DecodeString(testingKey)
	pubkey, _ = btcec.ParsePubKey(pubkeyBytes)

	os.Exit(m.Run())
}

func TestBuildCommitmentTx(t *testing.T) {
	builder := txbuilder.NewTxBuilder(
		wallet, nil, arklib.Bitcoin, vtxoTreeExpiry, boardingExitDelay,
	)

	fixtures, err := parseCommitmentTxFixtures()
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	if len(fixtures.Valid) > 0 {
		t.Run("valid", func(t *testing.T) {
			for _, f := range fixtures.Valid {
				cosignersPublicKeys := make([][]string, 0)

				for range f.Intents {
					randKey, err := btcec.NewPrivateKey()
					require.NoError(t, err)

					cosignersPublicKeys = append(cosignersPublicKeys, []string{
						hex.EncodeToString(randKey.PubKey().SerializeCompressed()),
					})
				}

				commitmentTx, vtxoTree, connAddr, _, err := builder.BuildCommitmentTx(
					pubkey, f.Intents, []ports.BoardingInput{}, cosignersPublicKeys,
				)
				require.NoError(t, err)
				require.NotEmpty(t, commitmentTx)
				require.NotEmpty(t, vtxoTree)
				require.Equal(t, connectorAddress, connAddr)
				require.Len(t, vtxoTree.Leaves(), f.ExpectedNumOfLeaves)

				roundPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
				require.NoError(t, err)

				err = tree.ValidateVtxoTree(
					vtxoTree, roundPtx, pubkey, vtxoTreeExpiry,
				)
				require.NoError(t, err)
			}
		})
	}

	if len(fixtures.Invalid) > 0 {
		t.Run("invalid", func(t *testing.T) {
			for _, f := range fixtures.Invalid {
				cosignersPublicKeys := make([][]string, 0)

				for range f.Intents {
					cosignersPublicKeys = append(cosignersPublicKeys, []string{
						hex.EncodeToString(pubkey.SerializeCompressed()),
					})
				}

				commitmentTx, vtxoTree, connAddr, _, err := builder.BuildCommitmentTx(
					pubkey, f.Intents, []ports.BoardingInput{}, cosignersPublicKeys,
				)
				require.EqualError(t, err, f.ExpectedErr)
				require.Empty(t, commitmentTx)
				require.Empty(t, connAddr)
				require.Empty(t, vtxoTree)
			}
		})
	}
}

func TestVerifyVtxoTapscriptSigs(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	builder := txbuilder.NewTxBuilder(
		wallet, &staticSigner{pubkey: signerKey.PubKey()},
		arklib.Bitcoin, vtxoTreeExpiry, boardingExitDelay,
	)

	t.Run("valid", func(t *testing.T) {
		t.Run("input without taproot leaf script is skipped", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			tx := buildTx(t, setup, nil)
			tx.Inputs[0].TaprootLeafScript = nil

			ok, ptx, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, tx), false)
			require.NoError(t, err)
			require.True(t, ok)
			require.NotNil(t, ptx)
		})

		t.Run("signed input accepted with mustIncludeSignerSig=false", func(t *testing.T) {
			// 2-of-2 closure (closureKey + signerKey): signer is pre-marked, only closureKey needs to sign.
			setup := newTwoKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			ok, ptx, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), false)
			require.NoError(t, err)
			require.True(t, ok)
			require.NotNil(t, ptx)
		})

		t.Run("all keys signed accepted with mustIncludeSignerSig=true", func(t *testing.T) {
			// 2-of-2 closure: both keys must sign when signer is not pre-marked.
			setup := newTwoKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig1 := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			sig2 := makeVtxoSig(t, setup.signerKey, packet, setup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig1, sig2}

			ok, ptx, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), true)
			require.NoError(t, err)
			require.True(t, ok)
			require.NotNil(t, ptx)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("wrong parity bit in control block", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			corrupted := make([]byte, len(setup.cbBytes))
			copy(corrupted, setup.cbBytes)
			corrupted[0] ^= 0x01

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, buildTx(t, setup, corrupted)), false)
			require.Error(t, err)
		})

		t.Run("wrong x-coordinate from tampered merkle path", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			fakeNode := make([]byte, 32)
			_, err := rand.Read(fakeNode)
			require.NoError(t, err)

			corrupted := append(append([]byte{}, setup.cbBytes...), fakeNode...)
			_, _, err = builder.VerifyVtxoTapscriptSigs(encodeTx(t, buildTx(t, setup, corrupted)), false)
			require.Error(t, err)
		})

		t.Run("invalid signature", func(t *testing.T) {
			setup := newSingleKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			sig.Signature[0] ^= 0xff
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), false)
			require.Error(t, err)
		})

		t.Run("missing signer signature when mustIncludeSignerSig=true", func(t *testing.T) {
			// 2-of-2 closure: signer is not pre-marked and doesn't sign → error.
			setup := newTwoKeyVtxoSetup(t, signerKey)
			packet := buildTx(t, setup, nil)

			sig := makeVtxoSig(t, setup.closureKey, packet, setup.leaf)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			_, _, err := builder.VerifyVtxoTapscriptSigs(encodeTx(t, packet), true)
			require.Error(t, err)
		})
	})
}

type commitmentTxFixtures struct {
	Valid []struct {
		Intents             []domain.Intent
		ExpectedNumOfLeaves int
	}
	Invalid []struct {
		Intents     []domain.Intent
		ExpectedErr string
	}
}

func parseCommitmentTxFixtures() (*commitmentTxFixtures, error) {
	file, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		return nil, err
	}
	v := map[string]interface{}{}
	if err := json.Unmarshal(file, &v); err != nil {
		return nil, err
	}

	vv := v["buildCommitmentTx"].(map[string]interface{})
	file, _ = json.Marshal(vv)
	var fixtures commitmentTxFixtures
	if err := json.Unmarshal(file, &fixtures); err != nil {
		return nil, err
	}

	return &fixtures, nil
}
