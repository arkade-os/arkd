package batchsessionhandler

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// recordingSignerSession records whether the tree ever reached the musig2 session.
type recordingSignerSession struct {
	tree.SignerSession
	pubkey    string
	initiated bool
}

func (s *recordingSignerSession) Init(_ []byte, _ int64, _ *tree.TxTree) error {
	s.initiated = true
	return nil
}

func (s *recordingSignerSession) GetPublicKey() string { return s.pubkey }

func (s *recordingSignerSession) GetNonces() (tree.TreeNonces, error) {
	return tree.TreeNonces{}, nil
}

// recordingClient records the nonce submissions so a test can assert nothing was
// sent for a tree that didn't validate.
type recordingClient struct {
	clientlib.Client
	submittedNonces int
}

func (c *recordingClient) SubmitTreeNonces(
	_ context.Context, _, _ string, _ tree.TreeNonces,
) error {
	c.submittedNonces++
	return nil
}

type treeSigningFixture struct {
	handler  *defaultHandler
	client   *recordingClient
	session  *recordingSignerSession
	event    clientlib.TreeSigningStartedEvent
	vtxoTree *tree.TxTree
}

// newTreeSigningFixture builds the batch a honest server would propose: a
// commitment tx paying the batch output and the vtxo tree spending it.
func newTreeSigningFixture(t *testing.T) *treeSigningFixture {
	t.Helper()

	forfeitPrvkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cosignerPrvkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	vtxoPrvkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	batchExpiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}

	sweepClosure := script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{forfeitPrvkey.PubKey()},
		},
		Locktime: batchExpiry,
	}
	sweepScript, err := sweepClosure.Script()
	require.NoError(t, err)

	sweepRoot := txscript.AssembleTaprootScriptTree(
		txscript.NewBaseTapLeaf(sweepScript),
	).RootNode.TapHash()

	vtxoPkScript, err := script.P2TRScript(vtxoPrvkey.PubKey())
	require.NoError(t, err)

	const receiverAmount = 10000
	leaf := tree.Leaf{
		Outputs: []tree.LeafOutput{
			{Amount: receiverAmount, Script: hex.EncodeToString(vtxoPkScript)},
		},
		CosignersPublicKeys: []string{
			hex.EncodeToString(cosignerPrvkey.PubKey().SerializeCompressed()),
		},
	}

	batchOutScript, batchOutAmount, err := tree.BuildBatchOutput(
		[]tree.Leaf{leaf}, sweepRoot[:],
	)
	require.NoError(t, err)

	prevoutHash, err := chainhash.NewHashFromStr(
		"49f8664acc899be91902f8ade781b7eeb9cbe22bdd9efbc36e56195de21bcd12",
	)
	require.NoError(t, err)

	commitmentTx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *prevoutHash, Index: 0}},
		[]*wire.TxOut{{Value: batchOutAmount, PkScript: batchOutScript}},
		3, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	commitmentTxHash := commitmentTx.UnsignedTx.TxHash()
	vtxoTree, err := tree.BuildVtxoTree(
		&wire.OutPoint{Hash: commitmentTxHash, Index: 0},
		[]tree.Leaf{leaf}, sweepRoot[:], batchExpiry,
	)
	require.NoError(t, err)

	encodedCommitmentTx, err := commitmentTx.B64Encode()
	require.NoError(t, err)

	addr := arklib.Address{
		HRP:        arklib.BitcoinRegTest.Addr,
		Signer:     forfeitPrvkey.PubKey(),
		VtxoTapKey: vtxoPrvkey.PubKey(),
	}
	encodedAddr, err := addr.EncodeV0()
	require.NoError(t, err)

	client := &recordingClient{}
	session := &recordingSignerSession{
		pubkey: hex.EncodeToString(cosignerPrvkey.PubKey().SerializeCompressed()),
	}

	return &treeSigningFixture{
		handler: &defaultHandler{
			Args: Args{
				Client: client,
				ServerParams: clientlib.ServerParams{
					Network:       arklib.BitcoinRegTest,
					ForfeitPubKey: forfeitPrvkey.PubKey(),
				},
				Receivers:      []clientlib.Receiver{{To: encodedAddr, Amount: receiverAmount}},
				SignerSessions: []tree.SignerSession{session},
			},
			batchExpiry: batchExpiry,
		},
		client:  client,
		session: session,
		event: clientlib.TreeSigningStartedEvent{
			Id:                   "batch-id",
			UnsignedCommitmentTx: encodedCommitmentTx,
			CosignersPubkeys:     []string{session.pubkey},
		},
		vtxoTree: vtxoTree,
	}
}

func TestOnTreeSigningStartedValidatesBeforeSigning(t *testing.T) {
	// the tree of a honest batch must still reach the musig2 session
	t.Run("valid", func(t *testing.T) {
		f := newTreeSigningFixture(t)

		skip, err := f.handler.OnTreeSigningStarted(
			context.Background(), f.event, f.vtxoTree,
		)
		require.NoError(t, err)
		require.False(t, skip)
		require.True(t, f.session.initiated)
		require.Equal(t, 1, f.client.submittedNonces)
	})

	// a tree not spending the batch output must be rejected before we contribute
	// anything to the signing session
	t.Run("not spending the batch output", func(t *testing.T) {
		f := newTreeSigningFixture(t)
		f.vtxoTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 1

		skip, err := f.handler.OnTreeSigningStarted(
			context.Background(), f.event, f.vtxoTree,
		)
		require.ErrorContains(t, err, "failed to verify vtxo tree")
		require.False(t, skip)
		require.False(t, f.session.initiated)
		require.Zero(t, f.client.submittedNonces)
	})

	// same for a tree we couldn't broadcast when we need to unroll
	t.Run("non final", func(t *testing.T) {
		f := newTreeSigningFixture(t)
		f.vtxoTree.Root.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1

		_, err := f.handler.OnTreeSigningStarted(
			context.Background(), f.event, f.vtxoTree,
		)
		require.ErrorContains(t, err, "unexpected sequence")
		require.False(t, f.session.initiated)
		require.Zero(t, f.client.submittedNonces)
	})

	// and for a tree not paying what we asked for
	t.Run("wrong receiver amount", func(t *testing.T) {
		f := newTreeSigningFixture(t)
		f.handler.Receivers[0].Amount++

		_, err := f.handler.OnTreeSigningStarted(
			context.Background(), f.event, f.vtxoTree,
		)
		require.ErrorContains(t, err, "offchain send output not found")
		require.False(t, f.session.initiated)
		require.Zero(t, f.client.submittedNonces)
	})
}
