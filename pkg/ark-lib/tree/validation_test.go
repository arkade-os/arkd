package tree_test

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	common "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateVtxoTree(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, testCase := range decodeFixtures(t).Valid {
			t.Run(testCase.Name, func(t *testing.T) {
				vtxoTree, commitmentTx, signerPubkey := testCase.decode(t)

				require.NoError(t, tree.ValidateVtxoTree(
					vtxoTree, commitmentTx, signerPubkey, testCase.expiry(),
				))
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, testCase := range decodeFixtures(t).Invalid {
			t.Run(testCase.Name, func(t *testing.T) {
				vtxoTree, commitmentTx, signerPubkey := testCase.decode(t)

				err := tree.ValidateVtxoTree(
					vtxoTree, commitmentTx, signerPubkey, testCase.expiry(),
				)
				require.Error(t, err)

				// The batch output check is the only failure that reports a
				// structured error, and both scripts have to reach the client so
				// it can report which key it was actually offered.
				if testCase.Err == errInvalidBatchOutputScript {
					arkErr := requireArkError(t, err, arkerrors.INVALID_BATCH_OUTPUT_SCRIPT)

					metadata := arkErr.Metadata()
					expected, actual := metadata["expected_pkscript"], metadata["actual_pkscript"]
					require.NotEmpty(t, expected)
					require.Equal(t,
						hex.EncodeToString(commitmentTx.UnsignedTx.TxOut[0].PkScript), actual,
					)
					require.NotEqual(t, expected, actual)
					return
				}

				sentinel, ok := fixtureSentinelErrs[testCase.Err]
				require.Truef(t, ok, "fixture declares unknown error %q", testCase.Err)
				require.ErrorIs(t, err, sentinel)
			})
		}
	})
}

//go:embed testdata/validation_fixtures.json
var validationFixturesJSON []byte

// errInvalidBatchOutputScript is the fixture name of the structured error the
// batch output binding reports. It is not a sentinel, so it is matched by code.
const errInvalidBatchOutputScript = "INVALID_BATCH_OUTPUT_SCRIPT"

// fixtureSentinelErrs maps the error names used by the fixtures onto the
// sentinels they stand for. Other SDKs match on the name.
var fixtureSentinelErrs = map[string]error{
	"EMPTY_TREE":                    tree.ErrEmptyTree,
	"NO_LEAVES":                     tree.ErrNoLeaves,
	"INVALID_TAPROOT_SCRIPT":        tree.ErrInvalidTaprootScript,
	"MISSING_COSIGNERS_PUBLIC_KEYS": tree.ErrMissingCosignersPublicKeys,
	"INVALID_AMOUNT":                tree.ErrInvalidAmount,
	"BATCH_OUTPUT_MISMATCH":         tree.ErrBatchOutputMismatch,
	"INVALID_BATCH_OUTPUTS_NUM":     tree.ErrInvalidBatchOutputsNum,
}

// fixtureFile is the on disk shape of the fixture file. Everything a validation
// run needs is in here, so the same file drives the check in any SDK.
type fixtureFile struct {
	Valid   []fixtureCase `json:"valid"`
	Invalid []fixtureCase `json:"invalid"`
}

type fixtureCase struct {
	Name string `json:"name"`
	// Err is empty for the valid fixtures, and names the expected failure for
	// the invalid ones.
	Err            string              `json:"err,omitempty"`
	SignerPubkey   string              `json:"signerPubkey"`
	VtxoTreeExpiry fixtureLocktime     `json:"vtxoTreeExpiry"`
	CommitmentTx   string              `json:"commitmentTx"`
	VtxoTree       []fixtureTxTreeNode `json:"vtxoTree"`
}

type fixtureLocktime struct {
	// Type is "block" or "second".
	Type  string `json:"type"`
	Value uint32 `json:"value"`
}

// fixtureTxTreeNode mirrors tree.TxTreeNode with explicit JSON names.
type fixtureTxTreeNode struct {
	Txid string `json:"txid"`
	// Tx is the base64 encoded PSBT of the node.
	Tx string `json:"tx"`
	// Children maps the node's output index to the child txid spending it.
	Children map[string]string `json:"children"`
}

func (c fixtureCase) expiry() common.RelativeLocktime {
	locktimeType := common.LocktimeTypeBlock
	if c.VtxoTreeExpiry.Type == "second" {
		locktimeType = common.LocktimeTypeSecond
	}

	return common.RelativeLocktime{Type: locktimeType, Value: c.VtxoTreeExpiry.Value}
}

// decode rebuilds the arguments ValidateVtxoTree takes from the fixture.
func (c fixtureCase) decode(t *testing.T) (*tree.TxTree, *psbt.Packet, *btcec.PublicKey) {
	t.Helper()

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(c.CommitmentTx), true)
	require.NoError(t, err)

	pubkeyBytes, err := hex.DecodeString(c.SignerPubkey)
	require.NoError(t, err)
	signerPubkey, err := btcec.ParsePubKey(pubkeyBytes)
	require.NoError(t, err)

	// An empty node list is how the fixtures carry the empty tree case.
	if len(c.VtxoTree) == 0 {
		return &tree.TxTree{}, commitmentTx, signerPubkey
	}

	flat := make(tree.FlatTxTree, 0, len(c.VtxoTree))
	for _, node := range c.VtxoTree {
		children := make(map[uint32]string, len(node.Children))
		for index, txid := range node.Children {
			outputIndex, err := strconv.ParseUint(index, 10, 32)
			require.NoError(t, err)
			children[uint32(outputIndex)] = txid
		}
		flat = append(flat, tree.TxTreeNode{
			Txid: node.Txid, Tx: node.Tx, Children: children,
		})
	}

	vtxoTree, err := tree.NewTxTree(flat)
	require.NoError(t, err)

	return vtxoTree, commitmentTx, signerPubkey
}

func decodeFixtures(t *testing.T) fixtureFile {
	t.Helper()

	var file fixtureFile
	require.NoError(t, json.Unmarshal(validationFixturesJSON, &file))
	require.NotEmpty(t, file.Valid)
	require.NotEmpty(t, file.Invalid)

	return file
}

func requireArkError[MT any](t *testing.T, err error, code arkerrors.Code[MT]) arkerrors.Error {
	t.Helper()

	var arkErr arkerrors.Error
	require.ErrorAs(t, err, &arkErr)
	require.Equal(t, code.Code, arkErr.Code())
	require.Equal(t, code.Name, arkErr.CodeName())
	require.Equal(t, code.GrpcCode, arkErr.GrpcCode())

	return arkErr
}
