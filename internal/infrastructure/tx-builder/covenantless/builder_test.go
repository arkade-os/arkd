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
	forfeitAddress   = "bc1py00yhcjpcj0k0sqra0etq0u3yy0purmspppsw0shyzyfe8c83tmq5h6kc2"
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
	wallet.On("GetForfeitAddress", mock.Anything).
		Return(forfeitAddress, nil)

	pubkeyBytes, _ := hex.DecodeString(testingKey)
	pubkey, _ = btcec.ParsePubKey(pubkeyBytes)

	os.Exit(m.Run())
}

func TestBuildCommitmentTx(t *testing.T) {
	builder := txbuilder.NewTxBuilder(
		wallet, arklib.Bitcoin, vtxoTreeExpiry, boardingExitDelay,
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
					pubkey, f.Intents, []ports.BoardingInput{}, []string{}, cosignersPublicKeys,
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
					pubkey, f.Intents, []ports.BoardingInput{}, []string{}, cosignersPublicKeys,
				)
				require.EqualError(t, err, f.ExpectedErr)
				require.Empty(t, commitmentTx)
				require.Empty(t, connAddr)
				require.Empty(t, vtxoTree)
			}
		})
	}
}

func randomInput() []ports.TxInput {
	txid := randomHex(32)
	input := &mockedInput{}
	input.On("GetAsset").Return("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
	input.On("GetValue").Return(uint64(1000))
	input.On("GetScript").Return("a914ea9f486e82efb3dd83a69fd96e3f0113757da03c87")
	input.On("GetTxid").Return(txid)
	input.On("GetIndex").Return(uint32(0))

	return []ports.TxInput{input}
}

func randomHex(len int) string {
	buf := make([]byte, len)
	// nolint
	rand.Read(buf)
	return hex.EncodeToString(buf)
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
