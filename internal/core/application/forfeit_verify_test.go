package application

import (
	"context"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/stretchr/testify/require"
)

// VerifyVtxoTapscriptSigs returns a nil packet with every error it reports.
type nilPacketTxBuilder struct {
	ports.TxBuilder // unimplemented methods panic on call
}

func (b nilPacketTxBuilder) VerifyVtxoTapscriptSigs(
	tx string, mustIncludeSignerSig bool,
) (bool, *psbt.Packet, error) {
	return false, nil, fmt.Errorf("invalid control block")
}

func TestVerifyForfeitTxsSigsSurvivesNilPacket(t *testing.T) {
	s := &service{builder: nilPacketTxBuilder{}}

	require.NotPanics(t, func() {
		convictions := s.verifyForfeitTxsSigs(
			context.Background(), "round-id", []string{"not-a-psbt"}, nil,
		)
		// extraction failed, so there is no vtxo to attribute a crime to
		require.Empty(t, convictions)
	})
}

// A conviction has to name the coin being forfeited. The leaf the tx carries is
// the sender's to choose, so it cannot be what the script is read from.
func TestExtractVtxoOutpointIgnoresTheAttachedLeaf(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	b64 := forfeitPsbt(t, func(p *psbt.Packet) {
		p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
			spendSig(priv.PubKey(), []byte{txscriptOpTrue}),
		}
		// deliberately no TaprootLeafScript: the outpoint does not come from it
	})

	outpoint, err := extractVtxoOutpointFromSignedForfeitTx(b64)
	require.NoError(t, err)

	var vtxoHash chainhash.Hash
	vtxoHash[0] = 0xaa
	require.Equal(t, vtxoHash.String(), outpoint.Txid)
	require.Equal(t, uint32(0), outpoint.VOut)
}
